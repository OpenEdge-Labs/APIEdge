# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Login, lockout, throttling, refresh rotation, password change and TOTP MFA (T-003)."""

from __future__ import annotations

import time

import pyotp
from fastapi.testclient import TestClient

from apiedge.app import create_app
from apiedge.config import Settings
from tests.integration.conftest import PASSWORD, World

LOGIN = "/api/v1/auth/login"


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.cookies.get("apiedge_csrf")
    if token is None:
        client.get("/healthz")
        token = client.cookies.get("apiedge_csrf")
    assert token
    return {"X-CSRF-Token": token}


def test_login_sets_httponly_cookies_and_me_works(world: World) -> None:
    c = world.client
    r = c.post(LOGIN, json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    cookies = r.headers.get_list("set-cookie")
    session = next(h for h in cookies if h.startswith("apiedge_session="))
    refresh = next(h for h in cookies if h.startswith("apiedge_refresh="))
    for h in (session, refresh):
        assert "HttpOnly" in h and "SameSite=strict" in h
    assert "Path=/api/v1/auth" in refresh
    me = c.get("/api/v1/auth/me").json()  # cookie-authenticated
    assert me["username"] == "alice" and me["tenant_id"] == world.tenant_a
    assert "user:create" in me["permissions"] and "tenant:create" not in me["permissions"]


def test_bad_password_and_unknown_user_look_the_same(world: World) -> None:
    r1 = world.client.post(LOGIN, json={"username": "alice", "password": "wrong-password-1"})
    r2 = world.client.post(LOGIN, json={"username": "nobody", "password": "wrong-password-1"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json() == {"detail": "invalid_credentials"}


def test_lockout_after_repeated_failures(world: World) -> None:
    for _ in range(world.settings.login_max_failures):
        world.client.post(LOGIN, json={"username": "victor", "password": "wrong-password-1"})
    r = world.client.post(LOGIN, json={"username": "victor", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "account_locked"
    # A wrong password while locked does not reveal the lock.
    r = world.client.post(LOGIN, json={"username": "victor", "password": "wrong-password-1"})
    assert r.json()["detail"] == "invalid_credentials"
    # An admin can unlock.
    h = world.login("alice")
    r = world.client.patch(
        f"/api/v1/tenants/{world.tenant_a}/users/{world.users['victor']}",
        json={"unlock": True},
        headers=h,
    )
    assert r.status_code == 200 and r.json()["is_locked"] is False
    world.login("victor")
    audit = world.client.get(
        f"/api/v1/tenants/{world.tenant_a}/audit?action=auth.lockout", headers=h
    ).json()
    assert audit and audit[0]["resource_id"] == str(world.users["victor"])


def test_login_throttled_per_ip(api_settings: Settings) -> None:
    settings = api_settings.model_copy(update={"login_rate_limit_per_minute": 3})
    with TestClient(create_app(settings)) as c:
        codes = [
            c.post(LOGIN, json={"username": "x", "password": "y"}).status_code for _ in range(4)
        ]
    assert codes == [401, 401, 401, 429]


def test_validation_rejects_unknown_fields_and_huge_passwords(world: World) -> None:
    r = world.client.post(LOGIN, json={"username": "a", "password": "b", "is_superadmin": True})
    assert r.status_code == 422
    r = world.client.post(LOGIN, json={"username": "a", "password": "x" * 300})
    assert r.status_code == 422


def test_unauthenticated_and_forged_tokens_rejected(world: World) -> None:
    assert world.client.get("/api/v1/auth/me").status_code == 401
    h = world.login("alice")
    token = h["Authorization"].split()[1]
    header, payload, sig = token.split(".")
    forged = {"Authorization": f"Bearer {header}.{payload}.{sig[:-2]}AA"}
    assert world.client.get("/api/v1/auth/me", headers=forged).status_code == 401
    none_alg = {"Authorization": "Bearer eyJhbGciOiJub25lIn0." + payload + "."}
    assert world.client.get("/api/v1/auth/me", headers=none_alg).status_code == 401


def test_refresh_rotates_and_reuse_revokes_family(world: World) -> None:
    c = world.client
    c.post(LOGIN, json={"username": "alice", "password": PASSWORD})
    first = c.cookies.get("apiedge_refresh")
    assert first
    r = c.post("/api/v1/auth/refresh", headers=_csrf(c))
    assert r.status_code == 200
    second = c.cookies.get("apiedge_refresh")
    assert second and second != first
    # Replaying the first (already rotated) token: theft detected, the whole family is revoked.
    c.cookies.clear()
    c.cookies.set("apiedge_refresh", first, path="/api/v1/auth")
    assert c.post("/api/v1/auth/refresh", headers=_csrf(c)).status_code == 401
    c.cookies.clear()
    c.cookies.set("apiedge_refresh", second, path="/api/v1/auth")
    assert c.post("/api/v1/auth/refresh", headers=_csrf(c)).status_code == 401


def test_cookie_auth_requires_csrf_token(world: World) -> None:
    c = world.client
    c.post(LOGIN, json={"username": "alice", "password": PASSWORD})
    assert c.post("/api/v1/auth/refresh").status_code == 403
    assert c.post("/api/v1/auth/refresh", headers=_csrf(c)).status_code == 200


def test_logout_revokes_refresh(world: World) -> None:
    c = world.client
    c.post(LOGIN, json={"username": "alice", "password": PASSWORD})
    raw = c.cookies.get("apiedge_refresh")
    assert c.post("/api/v1/auth/logout", headers=_csrf(c)).status_code == 204
    c.cookies.clear()
    c.cookies.set("apiedge_refresh", raw or "", path="/api/v1/auth")
    assert c.post("/api/v1/auth/refresh", headers=_csrf(c)).status_code == 401


def test_password_change_required_gate_and_session_invalidation(world: World) -> None:
    admin = world.login("alice")
    r = world.client.post(
        f"/api/v1/tenants/{world.tenant_a}/users/{world.users['dev']}/reset-password",
        json={"new_password": "Temporary-Pass-77"},
        headers=admin,
    )
    assert r.status_code == 204
    h = world.login("dev", "Temporary-Pass-77")
    assert world.client.get("/api/v1/auth/me", headers=h).json()["must_change_password"]
    r = world.client.get(f"/api/v1/tenants/{world.tenant_a}/users", headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "password_change_required"
    weak = world.client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "Temporary-Pass-77", "new_password": "short"},
        headers=h,
    )
    assert weak.status_code == 400
    r = world.client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "Temporary-Pass-77", "new_password": "Brand-New-Secret-9"},
        headers=h,
    )
    assert r.status_code == 200
    world.client.cookies.clear()
    # The old token is dead; the new one works without the gate.
    assert world.client.get("/api/v1/auth/me", headers=h).status_code == 401
    new = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert world.client.get(f"/api/v1/tenants/{world.tenant_a}", headers=new).status_code == 403
    assert world.client.get("/api/v1/auth/me", headers=new).json()["must_change_password"] is False


def test_totp_mfa_enrolment_and_login(world: World) -> None:
    h = world.login("alice")
    setup = world.client.post("/api/v1/auth/mfa/setup", headers=h).json()
    totp = pyotp.TOTP(setup["secret"])
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    bad = world.client.post("/api/v1/auth/mfa/enable", json={"code": "000000"}, headers=h)
    assert bad.status_code == 400
    code = totp.now()
    assert (
        world.client.post("/api/v1/auth/mfa/enable", json={"code": code}, headers=h).status_code
        == 204
    )
    r = world.client.post(LOGIN, json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "mfa_required"
    # The code used for enrolment cannot be replayed.
    r = world.client.post(
        LOGIN, json={"username": "alice", "password": PASSWORD, "totp_code": code}
    )
    assert r.status_code == 401 and r.json()["detail"] == "invalid_mfa_code"
    next_code = totp.at(int(time.time()) + totp.interval)
    world.login("alice", totp_code=next_code)


def test_admin_can_reset_user_mfa(world: World) -> None:
    h = world.login("victor")
    secret = world.client.post("/api/v1/auth/mfa/setup", headers=h).json()["secret"]
    world.client.post("/api/v1/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=h)
    admin = world.login("alice")
    r = world.client.patch(
        f"/api/v1/tenants/{world.tenant_a}/users/{world.users['victor']}",
        json={"reset_mfa": True},
        headers=admin,
    )
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    world.login("victor")


def test_disabled_tenant_blocks_login(world: World) -> None:
    root = world.login("root")
    r = world.client.patch(
        f"/api/v1/tenants/{world.tenant_b}", json={"is_active": False}, headers=root
    )
    assert r.status_code == 200
    r = world.client.post(LOGIN, json={"username": "bob", "password": PASSWORD})
    assert r.status_code == 401
