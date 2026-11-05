# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Built-in OAuth 2.0 authorization server and OIDC provider (T-023): admin API (RBAC, tenant
isolation, validation, secrets shown once, key rotation) and the gateway endpoints (client
credentials, authorization code with PKCE, refresh rotation with reuse detection, introspection,
revocation, userinfo, discovery, JWKS) and the ``jwt`` policy's built-in issuer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from apiedge.app import create_app
from apiedge.policies.jwt import b64url_decode
from tests.integration.conftest import PASSWORD
from tests.integration.test_gateway import Env, Upstream, upstreams  # noqa: F401 - fixture
from tests.integration.test_policies_gateway import env, gateway, set_policies  # noqa: F401

OAUTH = "/api/v1/tenants/{}/oauth"
REDIRECT = "https://app.example.com/callback"


@dataclass
class Ctx:
    env: Env
    admin: TestClient
    gw: TestClient
    headers: dict[str, str]

    def login(self, username: str) -> dict[str, str]:
        r = self.admin.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.admin.cookies.clear()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def client(self, tenant: int | None = None, **body: Any) -> dict[str, Any]:
        tenant = tenant or self.env.tenant_a
        headers = self.headers if tenant == self.env.tenant_a else self.login("bob")
        payload = {"name": f"c{secrets.token_hex(3)}", "grant_types": ["client_credentials"]}
        payload.update(body)
        r = self.admin.post(OAUTH.format(tenant) + "/clients", json=payload, headers=headers)
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out


@pytest.fixture
def ctx(env: Env) -> Iterator[Ctx]:  # noqa: F811 - pytest fixture parameter
    with TestClient(create_app(env.settings)) as admin, gateway(env) as gw:
        c = Ctx(env, admin, gw, {})
        c.headers = c.login("alice")
        yield c


def _basic(client_id: str, secret: str) -> dict[str, str]:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def _claims(token: str) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(b64url_decode(token.split(".")[1]))
    return out


def _token(gw: TestClient, data: dict[str, str], **kw: Any) -> Any:
    return gw.post("/acme/oauth2/token", data=data, **kw)


# --------------------------------------------------------------------------- admin API


def test_client_admin_rbac_validation_and_secret_handling(ctx: Ctx) -> None:
    base = OAUTH.format(ctx.env.tenant_a)
    created = ctx.client(name="backend", scopes=["orders.read", "orders.write"])
    assert created["client_secret"].startswith("cs_") and created["client_id"].startswith("cl_")
    assert created["secret_prefix"] == created["client_secret"][:8]
    got = ctx.admin.get(f"{base}/clients/{created['id']}", headers=ctx.headers).json()
    assert "client_secret" not in got and got["scopes"] == ["orders.read", "orders.write"]

    viewer, bob = ctx.login("victor"), ctx.login("bob")
    assert ctx.admin.get(base + "/clients", headers=viewer).status_code == 200
    assert ctx.admin.post(base + "/clients", json={}, headers=viewer).status_code == 403
    assert ctx.admin.post(base + "/keys", headers=viewer).status_code == 403
    assert ctx.admin.get(f"{base}/clients/{created['id']}", headers=bob).status_code == 404
    foreign = ctx.client(ctx.env.tenant_b)
    assert ctx.admin.get(f"{base}/clients/{foreign['id']}", headers=ctx.headers).status_code == 404

    for bad in (
        {"name": "p", "client_type": "public", "grant_types": ["client_credentials"]},
        {"name": "r", "grant_types": ["refresh_token"]},
        {"name": "a", "grant_types": ["authorization_code"]},  # no redirect URI
        {"name": "h", "grant_types": ["authorization_code"], "redirect_uris": ["http://x.io/cb"]},
        {"name": "f", "grant_types": ["authorization_code"], "redirect_uris": [REDIRECT + "#x"]},
        {"name": "o", "grant_types": ["client_credentials"], "scopes": ["openid"]},
        {"name": "s", "grant_types": ["client_credentials"], "scopes": ["bad scope"]},
    ):
        r = ctx.admin.post(base + "/clients", json=bad, headers=ctx.headers)
        assert r.status_code == 422, (bad, r.text)
    native = ctx.client(
        client_type="public",
        grant_types=["authorization_code"],
        redirect_uris=["com.example.app:/cb", "http://127.0.0.1:7777/cb"],
    )
    assert native["client_secret"] is None
    r = ctx.admin.post(f"{base}/clients/{native['id']}/secret", headers=ctx.headers)
    assert r.status_code == 409

    rotated = ctx.admin.post(f"{base}/clients/{created['id']}/secret", headers=ctx.headers)
    assert rotated.status_code == 200
    new_secret = rotated.json()["client_secret"]
    assert new_secret != created["client_secret"]
    old = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(created["client_id"], created["client_secret"]),
    )
    assert old.status_code == 401
    ok = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(created["client_id"], new_secret),
    )
    assert ok.status_code == 200, ok.text

    r = ctx.admin.patch(
        f"{base}/clients/{created['id']}", json={"enabled": False}, headers=ctx.headers
    )
    assert r.status_code == 200 and r.json()["enabled"] is False
    off = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(created["client_id"], new_secret),
    )
    assert off.status_code == 401
    assert ctx.admin.delete(f"{base}/clients/{created['id']}", headers=viewer).status_code == 403
    assert (
        ctx.admin.delete(f"{base}/clients/{created['id']}", headers=ctx.headers).status_code == 204
    )
    audit = ctx.admin.get(f"/api/v1/tenants/{ctx.env.tenant_a}/audit", headers=ctx.headers).json()
    text = json.dumps(audit)
    assert "oauth_client.create" in text and new_secret not in text
    assert created["client_secret"] not in text


def test_signing_key_rotation(ctx: Ctx) -> None:
    base = OAUTH.format(ctx.env.tenant_a)
    c = ctx.client()
    keys = ctx.admin.get(base + "/keys", headers=ctx.headers).json()
    assert [k["status"] for k in keys] == ["active"]
    assert "d" not in keys[0]["public_jwk"] and keys[0]["public_jwk"]["kty"] == "RSA"
    first = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(c["client_id"], c["client_secret"]),
    ).json()["access_token"]

    rotated = ctx.admin.post(base + "/keys", headers=ctx.headers)
    assert rotated.status_code == 201
    keys = ctx.admin.get(base + "/keys", headers=ctx.headers).json()
    assert [k["status"] for k in keys] == ["active", "retired"]
    jwks = ctx.gw.get("/acme/oauth2/jwks").json()
    assert {k["kid"] for k in jwks["keys"]} == {k["kid"] for k in keys}
    second = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(c["client_id"], c["client_secret"]),
    ).json()["access_token"]
    assert json.loads(b64url_decode(second.split(".")[0]))["kid"] == keys[0]["kid"]
    intro = ctx.gw.post(
        "/acme/oauth2/introspect",
        data={"token": first},
        headers=_basic(c["client_id"], c["client_secret"]),
    )
    assert intro.json()["active"] is True  # retired keys still validate

    active, retired = keys
    assert ctx.admin.delete(f"{base}/keys/{active['id']}", headers=ctx.headers).status_code == 409
    assert ctx.admin.delete(f"{base}/keys/{retired['id']}", headers=ctx.headers).status_code == 204
    intro = ctx.gw.post(
        "/acme/oauth2/introspect",
        data={"token": first},
        headers=_basic(c["client_id"], c["client_secret"]),
    )
    assert intro.json() == {"active": False}
    server = ctx.admin.get(base + "/server", headers=ctx.headers).json()
    assert server["issuer"].endswith("/acme/oauth2") and server["active_key_id"] == active["kid"]


# --------------------------------------------------------------------------- client credentials


def test_client_credentials_introspection_revocation_and_isolation(ctx: Ctx) -> None:
    c = ctx.client(scopes=["orders.read", "orders.write"], audiences=["orders-api"])
    auth = _basic(c["client_id"], c["client_secret"])
    meta = ctx.gw.get("/acme/oauth2/.well-known/openid-configuration").json()
    assert meta["issuer"] == "http://localhost:8081/acme/oauth2"
    assert meta["code_challenge_methods_supported"] == ["S256"]

    r = _token(ctx.gw, {"grant_type": "client_credentials", "scope": "orders.read"}, headers=auth)
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["token_type"] == "Bearer" and "refresh_token" not in body
    claims = _claims(body["access_token"])
    assert claims["sub"] == c["client_id"] and claims["scope"] == "orders.read"
    assert claims["aud"] == "orders-api" and claims["iss"] == meta["issuer"]

    post = _token(
        ctx.gw,
        {
            "grant_type": "client_credentials",
            "client_id": c["client_id"],
            "client_secret": c["client_secret"],
        },
    )
    assert post.status_code == 200 and _claims(post.json()["access_token"])["scope"] == (
        "orders.read orders.write"
    )
    for data, headers, code, error in (
        (
            {"grant_type": "client_credentials"},
            _basic(c["client_id"], "cs_wrong"),
            401,
            "invalid_client",
        ),
        ({"grant_type": "client_credentials"}, {}, 401, "invalid_client"),
        ({"grant_type": "client_credentials", "scope": "admin"}, auth, 400, "invalid_scope"),
        ({"grant_type": "client_credentials", "scope": "openid"}, auth, 400, "invalid_scope"),
        ({"grant_type": "password"}, auth, 400, "unsupported_grant_type"),
        ({"grant_type": "authorization_code", "code": "x"}, auth, 400, "unauthorized_client"),
    ):
        r = _token(ctx.gw, data, headers=headers)
        assert (r.status_code, r.json()["error"]) == (code, error), data
    assert (
        ctx.gw.post(
            "/acme/oauth2/token", json={"grant_type": "client_credentials"}, headers=auth
        ).status_code
        == 400
    )
    assert (
        ctx.gw.post(
            "/acme/oauth2/token?x=1",
            content=b"grant_type=a&grant_type=b",
            headers={**auth, "content-type": "application/x-www-form-urlencoded"},
        ).json()["error"]
        == "invalid_request"
    )

    # Another tenant's client is unknown here, and its tokens are not valid here.
    foreign = ctx.client(ctx.env.tenant_b)
    fauth = _basic(foreign["client_id"], foreign["client_secret"])
    assert _token(ctx.gw, {"grant_type": "client_credentials"}, headers=fauth).status_code == 401
    ftoken = ctx.gw.post(
        "/globex/oauth2/token", data={"grant_type": "client_credentials"}, headers=fauth
    ).json()["access_token"]
    access = body["access_token"]
    intro = ctx.gw.post("/acme/oauth2/introspect", data={"token": access}, headers=auth).json()
    assert intro["active"] is True and intro["client_id"] == c["client_id"]
    assert ctx.gw.post("/acme/oauth2/introspect", data={"token": ftoken}, headers=auth).json() == {
        "active": False
    }
    assert ctx.gw.post("/acme/oauth2/introspect", data={"token": access}).status_code == 401

    # Revocation by another client of the tenant is ignored; by the owner it takes effect.
    other = ctx.client()
    oauth_other = _basic(other["client_id"], other["client_secret"])
    assert (
        ctx.gw.post("/acme/oauth2/revoke", data={"token": access}, headers=oauth_other).status_code
        == 200
    )
    assert ctx.gw.post("/acme/oauth2/introspect", data={"token": access}, headers=auth).json()[
        "active"
    ]
    assert (
        ctx.gw.post("/acme/oauth2/revoke", data={"token": access}, headers=auth).status_code == 200
    )
    assert ctx.gw.post("/acme/oauth2/introspect", data={"token": access}, headers=auth).json() == {
        "active": False
    }
    assert ctx.gw.get("/nosuch/oauth2/jwks").status_code == 404
    assert ctx.gw.get("/acme/oauth2/other").status_code == 404


# --------------------------------------------------------------------------- authorization code


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def _authorize(
    ctx: Ctx, client_id: str, challenge: str, username: str = "dev", **extra: str
) -> Any:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "scope": "openid profile orders.read",
        "state": "st-1",
        "nonce": "n-1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    page = ctx.gw.get("/acme/oauth2/authorize", params=params)
    assert page.status_code == 200, page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    csrf = re.search(r"name='csrf' value='([^']+)'", page.text)
    assert csrf is not None
    form = {**params, "csrf": csrf.group(1), "username": username, "password": PASSWORD}
    form.update(extra)
    return ctx.gw.post("/acme/oauth2/authorize", data=form, follow_redirects=False)


def test_authorization_code_pkce_oidc_and_refresh_rotation(ctx: Ctx) -> None:
    c = ctx.client(
        grant_types=["authorization_code", "refresh_token"],
        redirect_uris=[REDIRECT],
        scopes=["openid", "profile", "orders.read"],
    )
    auth = _basic(c["client_id"], c["client_secret"])
    verifier, challenge = _pkce()

    bad = _authorize(ctx, c["client_id"], challenge, password="wrong")
    assert bad.status_code == 200 and "not correct" in bad.text
    foreign_user = _authorize(ctx, c["client_id"], challenge, username="bob")
    assert foreign_user.status_code == 200 and "not correct" in foreign_user.text

    r = _authorize(ctx, c["client_id"], challenge)
    assert r.status_code == 303, r.text
    loc = urlsplit(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == REDIRECT
    assert q["state"] == "st-1" and q["iss"].endswith("/acme/oauth2")
    code = q["code"]

    wrong = _token(
        ctx.gw,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": "x" * 50,
        },
        headers=auth,
    )
    assert wrong.json()["error"] == "invalid_grant"
    again = _token(
        ctx.gw,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        headers=auth,
    )
    assert again.json()["error"] == "invalid_grant"  # codes are single-use

    verifier, challenge = _pkce()
    q = parse_qs(urlsplit(_authorize(ctx, c["client_id"], challenge).headers["location"]).query)
    tokens = _token(
        ctx.gw,
        {
            "grant_type": "authorization_code",
            "code": q["code"][0],
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
        headers=auth,
    )
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    idt = _claims(body["id_token"])
    assert idt["aud"] == c["client_id"] and idt["nonce"] == "n-1"
    assert idt["preferred_username"] == "dev" and idt["sub"] == str(
        _claims(body["access_token"])["sub"]
    )
    info = ctx.gw.get(
        "/acme/oauth2/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert info.json() == {"sub": idt["sub"], "preferred_username": "dev"}

    first_refresh = body["refresh_token"]
    r1 = _token(
        ctx.gw, {"grant_type": "refresh_token", "refresh_token": first_refresh}, headers=auth
    )
    assert r1.status_code == 200, r1.text
    second_refresh = r1.json()["refresh_token"]
    assert second_refresh != first_refresh
    narrowed = _token(
        ctx.gw,
        {"grant_type": "refresh_token", "refresh_token": second_refresh, "scope": "openid admin"},
        headers=auth,
    )
    assert narrowed.json()["error"] == "invalid_scope"
    # Replaying the first refresh token revokes the whole family, the current one included.
    replay = _token(
        ctx.gw, {"grant_type": "refresh_token", "refresh_token": first_refresh}, headers=auth
    )
    assert replay.json()["error"] == "invalid_grant"
    after = _token(
        ctx.gw, {"grant_type": "refresh_token", "refresh_token": second_refresh}, headers=auth
    )
    assert after.json()["error"] == "invalid_grant"
    audit = ctx.admin.get(f"/api/v1/tenants/{ctx.env.tenant_a}/audit", headers=ctx.headers).text
    assert "oauth.refresh_reuse" in audit and "oauth.authorize" in audit


def test_authorize_request_validation_and_csrf(ctx: Ctx) -> None:
    c = ctx.client(grant_types=["authorization_code"], redirect_uris=[REDIRECT], scopes=["openid"])
    _, challenge = _pkce()
    base = {
        "response_type": "code",
        "client_id": c["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
    }
    # Unknown client or unregistered redirect: shown on the page, never redirected.
    for bad in ({"client_id": "cl_nope"}, {"redirect_uri": "https://evil.example/cb"}):
        r = ctx.gw.get("/acme/oauth2/authorize", params={**base, **bad}, follow_redirects=False)
        assert r.status_code == 400 and "location" not in r.headers
    for bad, error in (
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"scope": "admin"}, "invalid_scope"),
        ({"prompt": "none"}, "login_required"),
    ):
        r = ctx.gw.get("/acme/oauth2/authorize", params={**base, **bad}, follow_redirects=False)
        assert r.status_code == 303, bad
        q = parse_qs(urlsplit(r.headers["location"]).query)
        assert q["error"] == [error] and q["state"] == ["s"]
    # A form posted without the matching CSRF cookie is refused.
    ctx.gw.cookies.clear()
    r = ctx.gw.post(
        "/acme/oauth2/authorize",
        data={**base, "csrf": "forged", "username": "dev", "password": PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code == 200 and "expired" in r.text
    # Cross-tenant: the client of acme is unknown at globex.
    r = ctx.gw.get("/globex/oauth2/authorize", params=base, follow_redirects=False)
    assert r.status_code == 400


# --------------------------------------------------------------------------- jwt policy


def test_jwt_policy_with_builtin_issuer(
    ctx: Ctx,
    upstreams: dict[str, Upstream],  # noqa: F811
) -> None:
    api = ctx.env.add_api("/orders", [upstreams["a"].url])
    set_policies(
        ctx.env,
        api,
        [{"type": "jwt", "config": {"algorithms": ["RS256"], "builtin_issuer": True}}],
    )
    c = ctx.client()
    foreign = ctx.client(ctx.env.tenant_b)
    token = _token(
        ctx.gw,
        {"grant_type": "client_credentials"},
        headers=_basic(c["client_id"], c["client_secret"]),
    ).json()["access_token"]
    ftoken = ctx.gw.post(
        "/globex/oauth2/token",
        data={"grant_type": "client_credentials"},
        headers=_basic(foreign["client_id"], foreign["client_secret"]),
    ).json()["access_token"]
    with gateway(ctx.env) as gw:
        ok = gw.get("/acme/orders/1", headers={"Authorization": f"Bearer {token}"})
        assert ok.status_code == 200, ok.text
        assert (
            gw.get("/acme/orders/1", headers={"Authorization": f"Bearer {ftoken}"}).status_code
            == 401
        )
        assert gw.get("/acme/orders/1").status_code == 401
