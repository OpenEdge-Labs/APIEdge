# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Policy building blocks (T-008): JWT verification (HS/RS/PS/ES, JWKS, algorithm allow-list,
claims), configuration validation, rate-limit windows, the response cache and the client
address behind trusted proxies."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import pytest
from Crypto.Hash import SHA256, SHA384
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15, pss
from pydantic import TypeAdapter, ValidationError

from apiedge.gateway.app import client_address
from apiedge.policies.base import GatewayResponse, Pipeline, Policy, RequestContext
from apiedge.policies.builtin import build_pipeline
from apiedge.policies.config import PolicyChain, PolicySpec
from apiedge.policies.jwt import (
    JwksCache,
    JwtError,
    JwtVerifier,
    KeysUnavailableError,
    VerifyKey,
    check_claims,
    load_pem_key,
    parse_jwks,
)
from apiedge.policies.stores import CachedResponse, MemoryLimiter, RedisLimiter, ResponseCache

SECRET = b"s" * 32
RSA_KEY = RSA.generate(2048)
EC_KEY = ECC.generate(curve="P-256")
SPEC: TypeAdapter[Any] = TypeAdapter(PolicySpec)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token(header: dict[str, Any], claims: dict[str, Any], sign: Any = None) -> str:
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    alg = header.get("alg")
    if sign is not None:
        sig = sign(signing_input.encode())
    elif alg == "HS256":
        sig = hmac.new(SECRET, signing_input.encode(), hashlib.sha256).digest()
    elif alg == "RS256":
        sig = pkcs1_15.new(RSA_KEY).sign(SHA256.new(signing_input.encode()))
    elif alg == "PS384":
        sig = pss.new(RSA_KEY).sign(SHA384.new(signing_input.encode()))
    elif alg == "ES256":
        sig = DSS.new(EC_KEY, "fips-186-3").sign(SHA256.new(signing_input.encode()))
    else:
        sig = b""
    return f"{signing_input}.{b64(sig)}"


def claims(**extra: Any) -> dict[str, Any]:
    return {"sub": "alice", "exp": time.time() + 300, **extra}


def verifier(**kw: Any) -> JwtVerifier:
    base: dict[str, Any] = {
        "algorithms": frozenset({"HS256"}),
        "secret": SECRET,
        "public_key": None,
        "jwks_url": None,
        "jwks_ttl": 300,
        "jwks": None,
        "issuer": None,
        "audiences": frozenset(),
        "require_exp": True,
        "leeway": 0,
    }
    base.update(kw)
    return JwtVerifier(**base)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --------------------------------------------------------------------------- JWT


def test_hs256_token_verifies_and_returns_claims() -> None:
    out = run(verifier().verify(token({"alg": "HS256"}, claims())))
    assert out["sub"] == "alice"


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda: token({"alg": "none"}, claims()), "algorithm not allowed"),
        (lambda: token({"alg": "HS512"}, claims()), "algorithm not allowed"),
        (lambda: token({"alg": "HS256", "crit": ["x"]}, claims()), "unsupported critical header"),
        (lambda: token({"alg": "HS256"}, claims(), sign=lambda _d: b"bad"), "invalid signature"),
        (lambda: token({"alg": "HS256"}, {"sub": "a"}), "missing exp claim"),
        (lambda: token({"alg": "HS256"}, claims(exp=time.time() - 10)), "token expired"),
        (lambda: token({"alg": "HS256"}, claims(nbf=time.time() + 60)), "token not yet valid"),
        (lambda: token({"alg": "HS256"}, claims(exp="soon")), "invalid exp claim"),
        (lambda: "a.b", "malformed token"),
        (lambda: "x" * 9000, "token too large"),
        (lambda: b64(b'{"alg":"HS256"}') + ".e30.+++", "malformed token"),
    ],
)
def test_invalid_tokens_are_refused(make: Any, reason: str) -> None:
    with pytest.raises(JwtError, match=reason):  # tokens built now: claims use the clock
        run(verifier().verify(make()))


def test_issuer_audience_and_leeway() -> None:
    v = verifier(issuer="https://idp", audiences=frozenset({"api"}), leeway=30)
    ok = token({"alg": "HS256"}, claims(iss="https://idp", aud=["x", "api"]))
    assert run(v.verify(ok))["sub"] == "alice"
    with pytest.raises(JwtError, match="issuer"):
        run(v.verify(token({"alg": "HS256"}, claims(iss="https://evil", aud="api"))))
    with pytest.raises(JwtError, match="audience"):
        run(v.verify(token({"alg": "HS256"}, claims(iss="https://idp", aud="other"))))
    # within the leeway
    late = token({"alg": "HS256"}, claims(iss="https://idp", aud="api", exp=time.time() - 10))
    assert run(v.verify(late))
    check_claims(
        {"exp": 100}, issuer=None, audiences=frozenset(), require_exp=True, leeway=0, now=50
    )


def test_rsa_pss_and_ecdsa_with_pem_keys() -> None:
    rsa_pub = load_pem_key(RSA_KEY.public_key().export_key().decode())
    ec_pub = load_pem_key(EC_KEY.public_key().export_key(format="PEM"))
    rs = verifier(algorithms=frozenset({"RS256", "PS384"}), secret=None, public_key=rsa_pub)
    assert run(rs.verify(token({"alg": "RS256"}, claims())))
    assert run(rs.verify(token({"alg": "PS384"}, claims())))
    es = verifier(algorithms=frozenset({"ES256"}), secret=None, public_key=ec_pub)
    assert run(es.verify(token({"alg": "ES256"}, claims())))
    # an RSA key never verifies ES tokens and vice versa
    mixed = verifier(algorithms=frozenset({"ES256"}), secret=None, public_key=rsa_pub)
    with pytest.raises(JwtError):
        run(mixed.verify(token({"alg": "ES256"}, claims())))


def test_algorithm_confusion_hs_signed_with_public_key_is_refused() -> None:
    pem = RSA_KEY.public_key().export_key()
    v = verifier(
        algorithms=frozenset({"RS256"}), secret=None, public_key=load_pem_key(pem.decode())
    )
    forged = token(
        {"alg": "HS256"},
        claims(),
        sign=lambda d: hmac.new(pem, d, hashlib.sha256).digest(),
    )
    with pytest.raises(JwtError, match="algorithm not allowed"):
        run(v.verify(forged))


def test_small_rsa_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="2048"):
        weak = RSA.generate(1024)  # noqa: S505 - proves weak keys are refused
        load_pem_key(weak.public_key().export_key().decode())
    with pytest.raises(ValueError):
        load_pem_key("not a key")


def _jwk_rsa(kid: str) -> dict[str, Any]:
    pub = RSA_KEY.public_key()
    return {
        "kty": "RSA",
        "kid": kid,
        "n": b64(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
        "e": b64(pub.e.to_bytes(3, "big")),
    }


def test_parse_jwks_skips_symmetric_and_bad_keys() -> None:
    doc = {
        "keys": [
            _jwk_rsa("k1"),
            {"kty": "oct", "k": b64(SECRET), "kid": "sym"},
            {"kty": "RSA", "kid": "bad", "n": "!!", "e": "AQAB"},
            {**_jwk_rsa("enc"), "use": "enc"},
        ]
    }
    keys = parse_jwks(doc)
    assert [k.kid for k in keys] == ["k1"]
    with pytest.raises(ValueError):
        parse_jwks({"nope": []})


def test_jwks_cache_fetches_selects_by_kid_and_refreshes() -> None:
    calls: list[str] = []
    documents = [{"keys": [_jwk_rsa("old")]}, {"keys": [_jwk_rsa("new")]}]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=documents[min(len(calls) - 1, 1)])

    async def scenario() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        cache = JwksCache(lambda: client)
        v = verifier(
            algorithms=frozenset({"RS256"}),
            secret=None,
            jwks_url="https://idp.example/jwks",
            jwks=cache,
        )
        assert await v.verify(token({"alg": "RS256", "kid": "old"}, claims()))
        assert await v.verify(token({"alg": "RS256", "kid": "old"}, claims()))
        assert len(calls) == 1  # cached
        cache._entries["https://idp.example/jwks"].attempted_at -= 31  # refresh throttle passed
        # unknown kid: one refresh, which finds the rotated key
        assert await v.verify(token({"alg": "RS256", "kid": "new"}, claims()))
        assert len(calls) == 2
        # another unknown kid within the refresh interval: no further fetch
        with pytest.raises(JwtError, match="no matching key"):
            await v.verify(token({"alg": "RS256", "kid": "other"}, claims()))
        assert len(calls) == 2
        await client.aclose()

    run(scenario())


def test_jwks_failures_and_size_limit() -> None:
    def big(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + b" " * 70_000 + b"}")

    def down(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def scenario(handler: Any) -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        cache = JwksCache(lambda: client)
        with pytest.raises(KeysUnavailableError):
            await cache.keys("https://idp.example/jwks", 300)
        await client.aclose()

    run(scenario(big))
    run(scenario(down))


def test_verify_key_fits_only_its_algorithms() -> None:
    rsa = VerifyKey("RSA", RSA_KEY.public_key(), alg="RS256")
    assert rsa.fits("RS256") and not rsa.fits("RS384") and not rsa.fits("ES256")
    ec = VerifyKey("EC", EC_KEY.public_key())
    assert ec.fits("ES256") and not ec.fits("ES384")


# --------------------------------------------------------------------------- configuration


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "cors", "config": {"allow_origins": ["*"], "allow_credentials": True}},
        {"type": "cors", "config": {"allow_origins": ["javascript:alert(1)"]}},
        {"type": "transform", "config": {"request": {"set_headers": {"host": "evil"}}}},
        {"type": "transform", "config": {"request": {"set_headers": {"x-a": "1\r\nx-b: 2"}}}},
        {"type": "transform", "config": {"response": {"remove_headers": ["content-length"]}}},
        {"type": "transform", "config": {"request": {"set_json": {"a..b": 1}}}},
        {"type": "ip-filter", "config": {}},
        {"type": "ip-filter", "config": {"allow": ["300.1.1.1"]}},
        {"type": "jwt", "config": {"algorithms": ["HS256", "RS256"], "public_key": "x"}},
        {"type": "jwt", "config": {"algorithms": ["RS256"]}},
        {"type": "jwt", "config": {"algorithms": ["none"]}},
        {"type": "jwt", "config": {"algorithms": ["HS256"], "secret": "short"}},
        {"type": "jwt", "config": {"algorithms": ["RS256"], "jwks_url": "http://idp/jwks"}},
        {"type": "rate-limit", "config": {"limit": 0}},
        {"type": "mock", "config": {"status": 99}},
        {"type": "mock", "config": {"headers": {"content-length": "1"}}},
        {"type": "cache", "config": {"ttl_seconds": 0}},
        {"type": "script", "config": {}},
        {"type": "api-key", "config": {"header": "bad header"}},
        {"type": "api-key", "config": {}, "unknown": 1},
    ],
)
def test_invalid_policy_configs_are_rejected(spec: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SPEC.validate_python(spec)


def test_policy_ids_must_be_unique() -> None:
    with pytest.raises(ValidationError, match="unique"):
        PolicyChain.model_validate(
            {"policies": [{"id": "a", "type": "api-key"}, {"id": "a", "type": "mock"}]}
        )


def test_unusable_stored_policies_fail_closed() -> None:
    from apiedge.policies.builtin import PolicyServices

    services = PolicyServices(MemoryLimiter(), ResponseCache(1000), JwksCache(lambda: None))
    stored = json.dumps(
        [
            {"id": "p1", "type": "rate-limit", "config": {"limit": -1}},
            {"id": "p2", "type": "jwt", "config": {"algorithms": ["HS256"], "secret": "enc"}},
            {"id": "p3", "type": "mock", "enabled": False},
        ]
    )
    pipeline = build_pipeline(stored, tenant_id=1, api_id=1, keys={}, services=services, box=None)
    assert [p.id for p in pipeline.policies] == ["p1", "p2"]
    ctx = _ctx()
    answer, _ = run(pipeline.run_request(ctx, pipeline.policies))
    assert answer is not None and answer.status == 503
    assert ctx.trace[0].outcome == "error"
    broken = build_pipeline("{oops", tenant_id=1, api_id=1, keys={}, services=services, box=None)
    answer, _ = run(broken.run_request(_ctx(), broken.policies))
    assert answer is not None and answer.status == 503


def _ctx() -> RequestContext:
    return RequestContext(
        method="GET",
        path="/x",
        route="/*",
        query=[],
        raw_query="",
        headers=[],
        client_ip="203.0.113.5",
        request_id="r1",
    )


def test_pipeline_fails_closed_on_policy_exceptions_and_runs_response_in_reverse() -> None:
    order: list[str] = []

    class Boom(Policy):
        type = "boom"

        async def on_request(self, ctx: RequestContext) -> Any:
            raise RuntimeError("bug")

    class Mark(Policy):
        type = "mark"
        handles_response = True

        async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> Any:
            order.append(self.id)
            return "pass", ""

    p = Pipeline([Mark("a", frozenset()), Mark("b", frozenset()), Boom("c", frozenset())])
    ctx = _ctx()
    answer, ran = run(p.run_request(ctx, p.policies))
    assert answer is not None and answer.status == 500
    assert b"bug" not in (answer.body or b"")
    run(p.run_response(ctx, ran, answer))
    assert order == ["b", "a"]
    assert [t.outcome for t in ctx.trace][:3] == ["pass", "pass", "error"]


# --------------------------------------------------------------------------- stores


def test_memory_limiter_fixed_windows_and_bounded_keys() -> None:
    now = [1000.0]
    limiter = MemoryLimiter(max_keys=2, clock=lambda: now[0])
    assert limiter.hit_sync("a", 60).count == 1
    assert limiter.hit_sync("a", 60).count == 2
    w = limiter.hit_sync("a", 60)
    assert w.count == 3 and 0 < w.reset_after <= 60
    now[0] += 60
    assert limiter.hit_sync("a", 60).count == 1  # new window
    limiter.hit_sync("b", 60)
    limiter.hit_sync("c", 60)  # evicts the least recently used ("a")
    assert limiter.hit_sync("a", 60).count == 1


def test_redis_limiter_uses_redis_and_falls_back() -> None:
    class FakeRedis:
        def __init__(self) -> None:
            self.data: dict[str, int] = {}
            self.expiry: dict[str, int] = {}
            self.down = False

        async def incr(self, key: str) -> int:
            if self.down:
                raise ConnectionError("down")
            self.data[key] = self.data.get(key, 0) + 1
            return self.data[key]

        async def expire(self, key: str, seconds: int) -> None:
            self.expiry[key] = seconds

    redis = FakeRedis()
    limiter = RedisLimiter(redis)
    assert run(limiter.hit("k", 60)).count == 1
    assert run(limiter.hit("k", 60)).count == 2
    (name,) = redis.data
    assert name.startswith("apiedge:rl:") and "k" not in name.split(":")[2]
    assert redis.expiry[name] == 61
    redis.down = True
    assert run(limiter.hit("k", 60)).count == 1  # per-process fallback


def test_response_cache_lru_by_size_and_expiry() -> None:
    now = [0.0]
    cache = ResponseCache(max_bytes=700, clock=lambda: now[0])

    def entry(size: int, ttl: float = 10) -> CachedResponse:
        return CachedResponse(200, [], b"x" * size, now[0], now[0] + ttl)

    assert cache.put("a", entry(200))
    assert cache.put("b", entry(200))
    assert cache.get("a") is not None  # a is now most recently used
    assert cache.put("c", entry(200))  # 3 x 264 bytes > 700: evicts b
    assert cache.get("b") is None and cache.get("a") is not None
    assert not cache.put("huge", entry(1000))
    now[0] = 11
    assert cache.get("a") is None  # expired
    assert cache.size <= 700


# --------------------------------------------------------------------------- client address


@pytest.mark.parametrize(
    ("peer", "xff", "trusted", "expected"),
    [
        ("198.51.100.1", ["1.2.3.4"], [], "198.51.100.1"),  # no trusted proxies: XFF ignored
        ("10.0.0.1", ["1.2.3.4"], ["10.0.0.0/8"], "1.2.3.4"),
        ("10.0.0.1", ["6.6.6.6, 1.2.3.4, 10.0.0.2"], ["10.0.0.0/8"], "1.2.3.4"),
        ("10.0.0.1", ["garbage"], ["10.0.0.0/8"], "10.0.0.1"),
        ("198.51.100.1", ["1.2.3.4"], ["10.0.0.0/8"], "198.51.100.1"),  # untrusted peer
        ("::ffff:10.0.0.1", ["1.2.3.4"], ["10.0.0.0/8"], "1.2.3.4"),
        ("10.0.0.1", [], ["10.0.0.0/8"], "10.0.0.1"),
    ],
)
def test_client_address_behind_trusted_proxies(
    peer: str, xff: list[str], trusted: list[str], expected: str
) -> None:
    import ipaddress

    nets = [ipaddress.ip_network(c) for c in trusted]
    assert client_address(peer, xff, nets) == expected
