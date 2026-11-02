# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Built-in policies in the gateway (T-008): API keys, JWT, rate limits, transforms, CORS,
IP filters, caching, mocks, route scoping, the decision trace, analytics consumers and the
security edge cases of each (missing/forged/revoked credentials, cross-product and
cross-tenant keys, SSRF-guarded JWKS, caching of authenticated responses, header injection).

Upstreams are the real test servers of ``test_gateway``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apiedge.analytics.metrics import MetricsCollector
from apiedge.app import create_app
from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import Api, ApiKey
from apiedge.gateway.app import create_gateway_app
from apiedge.gateway.bus import ConfigBus
from apiedge.policies.base import RequestContext
from apiedge.policies.builtin import hash_api_key, secret_aad
from apiedge.security.crypto import load_secret_box
from tests.integration.conftest import PASSWORD, _seed
from tests.integration.test_gateway import (  # noqa: F401 - shared fixtures
    Env,
    Upstream,
    _clear_hits,
    _settings,
    _wait_for,
    fake_resolver,
    upstreams,
)

SECRET = "an-hs256-shared-secret-of-32-bytes!"
CLIENT = ("203.0.113.9", 50000)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    settings = _settings(tmp_path, gateway_trusted_proxies=["10.0.0.0/8"])
    a, b, _users = _seed(settings)
    return Env(settings, a, b)


def _session(env: Env) -> Any:
    return make_session_factory(make_engine(env.settings.effective_database_url))()


def set_policies(env: Env, api_id: int, policies: list[dict[str, Any]]) -> None:
    """Store a chain as the admin API would (secrets encrypted)."""
    box = load_secret_box(env.settings)
    assert box is not None
    stored = []
    for i, p in enumerate(policies):
        p = {"id": p.get("id", f"p{i}"), "enabled": True, "routes": [], **p}
        cfg = dict(p.get("config", {}))
        if p["type"] == "jwt" and cfg.get("secret"):
            cfg["secret"] = box.encrypt(cfg["secret"], secret_aad(api_id, p["id"], "secret"))
        p["config"] = cfg
        stored.append(p)
    with _session(env) as s:
        api = s.get(Api, api_id)
        api.policies = json.dumps(stored)
        s.commit()


def add_key(
    env: Env, api_id: int, name: str = "mobile", *, revoked: bool = False, expired: bool = False
) -> str:
    plain = f"ak_test_{name}_{hashlib.sha256(name.encode()).hexdigest()[:20]}"
    with _session(env) as s:
        api = s.get(Api, api_id)
        now = datetime.now(timezone.utc)
        s.add(
            ApiKey(
                tenant_id=api.tenant_id,
                product_id=api.product_id,
                name=name,
                prefix=plain[:11],
                key_hash=hash_api_key(plain),
                revoked_at=now if revoked else None,
                expires_at=now - timedelta(seconds=1) if expired else None,
            )
        )
        s.commit()
    return plain


def gateway(env: Env, **kw: Any) -> TestClient:
    client = kw.pop("client", CLIENT)
    app = create_gateway_app(env.settings, kw.pop("bus", None), resolver=fake_resolver, **kw)
    return TestClient(app, client=client)


def upstream_headers(r: Any) -> dict[str, str]:
    return {k: v for k, v in r.json()["headers"]}


# --------------------------------------------------------------------------- API keys


def test_api_key_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    other = env.add_api("/other", [upstreams["a"].url])  # another product
    foreign = env.add_api("/foreign", [upstreams["a"].url], tenant=env.tenant_b)
    set_policies(env, api, [{"type": "api-key", "config": {"query_param": "apikey"}}])
    good = add_key(env, api, "mobile")
    revoked = add_key(env, api, "old", revoked=True)
    expired = add_key(env, api, "expired", expired=True)
    other_product = add_key(env, other, "otherprod")
    other_tenant = add_key(env, foreign, "globex")
    metrics = MetricsCollector()
    with gateway(env, metrics=metrics) as gw:
        r = gw.get("/acme/orders/1")
        assert r.status_code == 401
        assert r.json()["error"] == "unauthorized" and "request_id" in r.json()
        assert r.headers["www-authenticate"].startswith("APIKey")
        for bad in (revoked, expired, other_product, other_tenant, "ak_guess", "x" * 5000):
            assert gw.get("/acme/orders/1", headers={"x-api-key": bad}).status_code == 401, bad
        r = gw.get("/acme/orders/1", headers={"x-api-key": good})
        assert r.status_code == 200
        assert "x-api-key" not in upstream_headers(r)  # not forwarded upstream
        r = gw.get("/acme/orders/1?apikey=" + good + "&keep=1")
        assert r.status_code == 200 and r.json()["query"] == "keep=1"
        # No policy on the other API: still open.
        assert gw.get("/acme/other/1").status_code == 200
        consumers = {key[6] for key in metrics.drain()}  # before the shutdown flush
    assert "key:mobile" in consumers and "" in consumers


def test_key_management_and_revocation_through_admin_api(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    bus = ConfigBus()
    with TestClient(create_app(env.settings, bus)) as admin, gateway(env, bus=bus) as gw:
        r = admin.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        admin.cookies.clear()
        base = f"/api/v1/tenants/{env.tenant_a}/products"
        pid = admin.post(base, json={"name": "Shop"}, headers=h).json()["id"]
        api = admin.post(
            f"{base}/{pid}/apis",
            json={
                "name": "Live",
                "base_path": "/live",
                "upstreams": [{"url": upstreams["a"].url}],
                "routes": [{"methods": ["GET"], "path": "/*"}],
            },
            headers=h,
        ).json()["id"]
        r = admin.put(
            f"{base}/{pid}/apis/{api}/policies",
            json={"policies": [{"type": "api-key"}]},
            headers=h,
        )
        assert r.status_code == 200, r.text
        admin.post(f"{base}/{pid}/apis/{api}/lifecycle", json={"lifecycle": "published"}, headers=h)
        _wait_for(gw, "/acme/live/x", 401)
        created = admin.post(f"{base}/{pid}/api-keys", json={"name": "app"}, headers=h).json()
        key = created["key"]
        deadline = time.monotonic() + 10
        while gw.get("/acme/live/x", headers={"x-api-key": key}).status_code != 200:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        r = admin.post(f"{base}/{pid}/api-keys/{created['id']}/revoke", headers=h)
        assert r.status_code == 200 and r.json()["status"] == "revoked"
        deadline = time.monotonic() + 10
        while gw.get("/acme/live/x", headers={"x-api-key": key}).status_code != 401:
            assert time.monotonic() < deadline
            time.sleep(0.05)


# --------------------------------------------------------------------------- JWT


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hs_token(claims: dict[str, Any], alg: str = "HS256", secret: str = SECRET) -> str:
    head = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64(json.dumps(claims).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig) if alg != 'none' else ''}"


def test_jwt_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    cfg = {"algorithms": ["HS256"], "secret": SECRET, "issuer": "https://idp", "audiences": ["o"]}
    set_policies(env, api, [{"type": "jwt", "config": cfg}])
    good = {"sub": "user-7", "iss": "https://idp", "aud": "o", "exp": time.time() + 60}
    metrics = MetricsCollector()
    with gateway(env, metrics=metrics) as gw:
        r = gw.get("/acme/orders/1")
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
        r = gw.get("/acme/orders/1", headers={"authorization": f"Bearer {hs_token(good)}"})
        assert r.status_code == 200
        assert upstream_headers(r)["authorization"].startswith("Bearer ")  # kept by default
        bad = [
            hs_token({**good, "exp": time.time() - 3600}),
            hs_token({**good, "iss": "https://evil"}),
            hs_token({**good, "aud": "x"}),
            hs_token(good, secret="another-secret-that-is-32-bytes-long"),
            hs_token(good, alg="none"),
            "not-a-token",
        ]
        for tok in bad:
            r = gw.get("/acme/orders/1", headers={"authorization": f"Bearer {tok}"})
            assert r.status_code == 401, tok
            assert "invalid_token" in r.headers["www-authenticate"]
        r = gw.get("/acme/orders/1", headers={"authorization": f"Basic {hs_token(good)}"})
        assert r.status_code == 401
        assert "jwt:user-7" in {key[6] for key in metrics.drain()}


def test_jwks_fetch_goes_through_the_ssrf_guard(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    # rebind.test now resolves to the cloud metadata address: the fetch must be refused.
    cfg = {"algorithms": ["RS256"], "jwks_url": "https://rebind.test/jwks"}
    set_policies(env, api, [{"type": "jwt", "config": cfg}])
    tok = hs_token({"sub": "a", "exp": time.time() + 60}).split(".")
    head = _b64(json.dumps({"alg": "RS256", "kid": "k"}).encode())
    with gateway(env) as gw:
        r = gw.get("/acme/orders/1", headers={"authorization": f"Bearer {head}.{tok[1]}.{tok[2]}"})
        assert r.status_code == 503
        assert r.json()["error"] == "auth_unavailable"
        assert "169.254" not in r.text


# --------------------------------------------------------------------------- rate limits


def test_rate_limit_per_consumer_and_ip(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        env,
        api,
        [
            {"type": "api-key"},
            {"type": "rate-limit", "config": {"limit": 2, "window_seconds": 60}},
        ],
    )
    k1, k2 = add_key(env, api, "one"), add_key(env, api, "two")
    with gateway(env) as gw:
        r = gw.get("/acme/orders/1", headers={"x-api-key": k1})
        assert r.status_code == 200
        assert r.headers["ratelimit-limit"] == "2" and r.headers["ratelimit-remaining"] == "1"
        assert r.headers["ratelimit-policy"] == "2;w=60"
        assert gw.get("/acme/orders/1", headers={"x-api-key": k1}).status_code == 200
        r = gw.get("/acme/orders/1", headers={"x-api-key": k1})
        assert r.status_code == 429
        assert 1 <= int(r.headers["retry-after"]) <= 60
        assert r.headers["ratelimit-remaining"] == "0"
        assert gw.get("/acme/orders/1", headers={"x-api-key": k2}).status_code == 200

    api2 = env.add_api("/byip", [upstreams["a"].url])
    set_policies(env, api2, [{"type": "rate-limit", "config": {"limit": 1, "key_by": "ip"}}])
    with gateway(env, client=("10.0.0.5", 1)) as gw:  # a trusted proxy
        assert gw.get("/acme/byip/1", headers={"x-forwarded-for": "1.1.1.1"}).status_code == 200
        assert gw.get("/acme/byip/1", headers={"x-forwarded-for": "1.1.1.1"}).status_code == 429
        assert gw.get("/acme/byip/1", headers={"x-forwarded-for": "2.2.2.2"}).status_code == 200
    with gateway(env) as gw:  # untrusted peer: a forged X-Forwarded-For does not help
        assert gw.get("/acme/byip/1", headers={"x-forwarded-for": "3.3.3.3"}).status_code == 200
        assert gw.get("/acme/byip/1", headers={"x-forwarded-for": "4.4.4.4"}).status_code == 429


# --------------------------------------------------------------------------- transforms


def test_transform_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        env,
        api,
        [
            {"type": "api-key"},
            {
                "type": "transform",
                "config": {
                    "request": {
                        "set_headers": {"x-consumer": "{consumer}", "x-static": "1"},
                        "remove_headers": ["x-debug"],
                        "set_query": {"v": "2"},
                        "remove_query": ["secret"],
                        "set_json": {"meta.source": "gateway"},
                        "remove_json": ["password"],
                    },
                    "response": {
                        "set_headers": {"x-powered-by": "APIEdge"},
                        "remove_headers": ["x-upstream"],
                        "remove_json": ["headers"],
                        "set_json": {"wrapped": True},
                    },
                },
            },
        ],
    )
    key = add_key(env, api, "tx")
    with gateway(env) as gw:
        r = gw.post(
            "/acme/orders/1?secret=s&keep=1&v=1",
            headers={"x-api-key": key, "x-debug": "1", "content-type": "application/json"},
            content=json.dumps({"password": "p", "item": 1}),
        )
        assert r.status_code == 200, r.text
        assert r.headers["x-powered-by"] == "APIEdge" and "x-upstream" not in r.headers
        out = r.json()
        assert "headers" not in out and out["wrapped"] is True
        assert out["query"] == "keep=1&v=2"
        assert json.loads(out["body"]) == {"item": 1, "meta": {"source": "gateway"}}
        assert int(r.headers["content-length"]) == len(r.content)
        # Non-JSON bodies are left alone.
        r = gw.post(
            "/acme/orders/text",
            headers={"x-api-key": key, "content-type": "text/plain"},
            content=b"password=p",
        )
        assert r.status_code == 200 and r.text.count("password=p") == 1
    hits = upstreams["a"].hits
    sent = dict(hits[0]["headers"])
    assert sent["x-consumer"] == "key:tx" and sent["x-static"] == "1" and "x-debug" not in sent


# --------------------------------------------------------------------------- CORS


def test_cors_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url], routes=(("GET,POST", "/*"),))
    set_policies(
        env,
        api,
        [
            {
                "type": "cors",
                "config": {
                    "allow_origins": ["https://app.example"],
                    "allow_methods": ["GET", "POST"],
                    "allow_headers": ["x-api-key"],
                    "expose_headers": ["x-request-id"],
                    "allow_credentials": True,
                },
            },
            {"type": "api-key"},
        ],
    )
    key = add_key(env, api, "web")
    pre = {
        "origin": "https://app.example",
        "access-control-request-method": "POST",
        "access-control-request-headers": "X-API-Key, Content-Type",
    }
    with gateway(env) as gw:
        # Preflight: answered before the API key check, although OPTIONS is not a route method.
        r = gw.options("/acme/orders/1", headers=pre)
        assert r.status_code == 204 and r.content == b""
        assert "content-length" not in r.headers
        assert r.headers["access-control-allow-origin"] == "https://app.example"
        assert r.headers["access-control-allow-credentials"] == "true"
        assert "POST" in r.headers["access-control-allow-methods"]
        assert "x-api-key" in r.headers["access-control-allow-headers"]
        assert not upstreams["a"].hits
        bad_origin = {**pre, "origin": "https://evil.example"}
        r = gw.options("/acme/orders/1", headers=bad_origin)
        assert r.status_code == 403
        assert "access-control-allow-origin" not in r.headers
        r = gw.options("/acme/orders/1", headers={**pre, "access-control-request-method": "PUT"})
        assert r.status_code == 403
        r = gw.options(
            "/acme/orders/1", headers={**pre, "access-control-request-headers": "x-admin"}
        )
        assert r.status_code == 403
        # Actual requests, including rejected ones, carry CORS headers for allowed origins.
        r = gw.get("/acme/orders/1", headers={"origin": "https://app.example", "x-api-key": key})
        assert r.status_code == 200
        assert r.headers["access-control-allow-origin"] == "https://app.example"
        assert r.headers["access-control-expose-headers"] == "x-request-id"
        assert "Origin" in r.headers["vary"]
        r = gw.get("/acme/orders/1", headers={"origin": "https://app.example"})
        assert r.status_code == 401
        assert r.headers["access-control-allow-origin"] == "https://app.example"
        r = gw.get("/acme/orders/1", headers={"origin": "https://evil.example", "x-api-key": key})
        assert r.status_code == 200 and "access-control-allow-origin" not in r.headers


# --------------------------------------------------------------------------- IP filter


def test_ip_filter_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        env,
        api,
        [{"type": "ip-filter", "config": {"allow": ["203.0.113.0/24"], "deny": ["203.0.113.66"]}}],
    )
    with gateway(env) as gw:
        assert gw.get("/acme/orders/1").status_code == 200
        # A client-supplied X-Forwarded-For from an untrusted peer is ignored.
        r = gw.get("/acme/orders/1", headers={"x-forwarded-for": "198.51.100.1"})
        assert r.status_code == 200
    with gateway(env, client=("203.0.113.66", 1)) as gw:
        assert gw.get("/acme/orders/1").status_code == 403
    with gateway(env, client=("198.51.100.1", 1)) as gw:
        r = gw.get("/acme/orders/1", headers={"x-forwarded-for": "203.0.113.9"})
        assert r.status_code == 403 and r.json()["error"] == "forbidden"
    with gateway(env, client=("10.1.2.3", 1)) as gw:  # trusted proxy
        assert (
            gw.get("/acme/orders/1", headers={"x-forwarded-for": "203.0.113.9"}).status_code == 200
        )
        r = gw.get("/acme/orders/1", headers={"x-forwarded-for": "203.0.113.9, 198.51.100.7"})
        assert r.status_code == 403  # the right-most untrusted hop is the client


# --------------------------------------------------------------------------- cache


def test_cache_policy(env: Env, upstreams: dict[str, Upstream]) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(env, api, [{"type": "cache", "config": {"ttl_seconds": 60}}])
    hits = upstreams["a"].hits
    with gateway(env) as gw:
        first = gw.get("/acme/orders/1?q=1")
        assert first.headers["x-cache"] == "MISS"
        second = gw.get("/acme/orders/1?q=1")
        assert second.headers["x-cache"] == "HIT" and second.json() == first.json()
        assert "age" in second.headers
        assert second.headers["x-request-id"] != first.headers["x-request-id"]
        assert len(hits) == 1
        assert gw.get("/acme/orders/1?q=2").headers["x-cache"] == "MISS"  # query is in the key
        assert len(hits) == 2
        # Authenticated requests are neither served from nor stored in the cache.
        r = gw.get("/acme/orders/1?q=1", headers={"authorization": "Bearer x"})
        assert "x-cache" not in r.headers
        assert len(hits) == 3
        # Unsafe methods, no-store answers, cookies and client no-cache are respected.
        gw.post("/acme/orders/1?q=1")
        assert len(hits) == 4
        for _ in range(2):
            gw.get("/acme/orders/nostore")
            gw.get("/acme/orders/hop")  # sets cookies
            gw.cookies.clear()  # (a request with a Cookie header would bypass the cache)
        assert len(hits) == 8
        r = gw.get("/acme/orders/1?q=1", headers={"cache-control": "no-cache"})
        assert r.headers["x-cache"] == "MISS" and len(hits) == 9
        # Accept is part of the key.
        r = gw.get("/acme/orders/1?q=1", headers={"accept": "text/csv"})
        assert r.headers["x-cache"] == "MISS"


def test_cache_of_authenticated_responses_is_per_consumer(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        env,
        api,
        [{"type": "api-key"}, {"type": "cache", "config": {"cache_authenticated": True}}],
    )
    k1, k2 = add_key(env, api, "c1"), add_key(env, api, "c2")
    with gateway(env) as gw:
        assert gw.get("/acme/orders/1", headers={"x-api-key": k1}).headers["x-cache"] == "MISS"
        assert gw.get("/acme/orders/1", headers={"x-api-key": k1}).headers["x-cache"] == "HIT"
        assert gw.get("/acme/orders/1", headers={"x-api-key": k2}).headers["x-cache"] == "MISS"
        assert gw.get("/acme/orders/1").status_code == 401  # never served without a key


# --------------------------------------------------------------------------- mock, scoping, trace


def test_mock_route_scoping_disabled_policies_and_trace(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    api = env.add_api(
        "/orders", [upstreams["a"].url], routes=(("GET", "/mocked"), ("GET,HEAD", "/real/*"))
    )
    set_policies(
        env,
        api,
        [
            {
                "id": "deny",
                "type": "ip-filter",
                "enabled": False,
                "config": {"deny": ["0.0.0.0/0"]},
            },
            {
                "id": "mock1",
                "type": "mock",
                "routes": ["/mocked"],
                "config": {"status": 201, "body": '{"ok":true}', "headers": {"x-mock": "1"}},
            },
        ],
    )
    traces: list[tuple[RequestContext, int]] = []
    app = create_gateway_app(env.settings, resolver=fake_resolver)
    app.state.runtime.trace_listeners.append(lambda ctx, resp: traces.append((ctx, resp.status)))
    with TestClient(app, client=CLIENT) as gw:
        r = gw.get("/acme/orders/mocked")
        assert r.status_code == 201 and r.json() == {"ok": True} and r.headers["x-mock"] == "1"
        assert gw.head("/acme/orders/real/x").status_code == 200
        assert gw.get("/acme/orders/real/x").headers["x-upstream"] == "a"
    assert len(upstreams["a"].hits) == 2
    ctx, status = traces[0]
    assert status == 201
    assert [t.as_dict()["policy_id"] for t in ctx.trace] == ["mock1"]
    assert ctx.trace[0].outcome == "respond"
    assert traces[2][0].trace == []  # the mock is scoped to /mocked


def test_secrets_are_encrypted_and_bad_ciphertext_fails_closed(
    env: Env, upstreams: dict[str, Upstream]
) -> None:
    api = env.add_api("/orders", [upstreams["a"].url])
    set_policies(env, api, [{"type": "jwt", "config": {"algorithms": ["HS256"], "secret": SECRET}}])
    with _session(env) as s:
        stored = s.scalars(select(Api.policies).where(Api.id == api)).one()
        assert SECRET not in stored
        tampered = json.loads(stored)
        tampered[0]["config"]["secret"] = SECRET  # plaintext is not a valid ciphertext
        s.get(Api, api).policies = json.dumps(tampered)
        s.commit()
    with gateway(env) as gw:
        tok = hs_token({"sub": "a", "exp": time.time() + 60})
        r = gw.get("/acme/orders/1", headers={"authorization": f"Bearer {tok}"})
        assert r.status_code == 503 and r.json()["error"] == "policy_unavailable"
    assert not upstreams["a"].hits
