# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Admin API for policy chains and API keys (T-008): validation, write-only encrypted secrets,
SSRF-checked JWKS URLs, keys shown once and stored hashed, RBAC denial, product scoping,
cross-tenant isolation and audit events."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from sqlalchemy import select

from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import Api, ApiKey, AuditEvent
from tests.integration.conftest import World

PUBLIC = "http://93.184.216.34/"
SECRET = "an-hs256-shared-secret-of-32-bytes!"


def _base(world: World, tenant: int | None = None) -> str:
    return f"/api/v1/tenants/{tenant or world.tenant_a}/products"


def _setup(world: World, h: dict[str, str], tenant: int | None = None) -> tuple[int, int]:
    base = _base(world, tenant)
    r = world.client.post(base, json={"name": "Shop"}, headers=h)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    r = world.client.post(
        f"{base}/{pid}/apis",
        json={
            "name": "Orders",
            "base_path": "/orders",
            "upstreams": [{"url": PUBLIC}],
            "routes": [{"methods": ["GET"], "path": "/orders"}, {"methods": ["GET"], "path": "/*"}],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    return pid, r.json()["id"]


def _chain_url(world: World, pid: int, api: int, tenant: int | None = None) -> str:
    return f"{_base(world, tenant)}/{pid}/apis/{api}/policies"


def _db(world: World) -> Any:
    return make_session_factory(make_engine(world.settings.effective_database_url))()


JWT = {"type": "jwt", "name": "IdP tokens", "config": {"algorithms": ["HS256"], "secret": SECRET}}


def test_policy_chain_crud_and_write_only_secrets(world: World) -> None:
    h = world.login("alice")
    pid, api = _setup(world, h)
    url = _chain_url(world, pid, api)
    r = world.client.get(url, headers=h)
    assert r.status_code == 200 and r.json() == {"policies": [], "secrets_set": {}}

    chain = [
        {"type": "cors", "config": {"allow_origins": ["https://app.example"]}},
        JWT,
        {"type": "rate-limit", "routes": ["/orders"], "config": {"limit": 10}},
        {"type": "mock", "enabled": False},
    ]
    r = world.client.put(url, json={"policies": chain}, headers=h)
    assert r.status_code == 200, r.text
    out = r.json()
    ids = [p["id"] for p in out["policies"]]
    assert len(set(ids)) == 4
    assert [p["type"] for p in out["policies"]] == ["cors", "jwt", "rate-limit", "mock"]
    jwt_id = ids[1]
    assert out["policies"][1]["config"]["secret"] is None
    assert out["secrets_set"] == {jwt_id: ["secret"]}
    assert SECRET not in r.text

    with _db(world) as s:
        stored = s.get(Api, api).policies
    assert SECRET not in stored
    assert json.loads(stored)[1]["config"]["secret"]  # encrypted value kept

    # Sending the policy back with secret = null keeps the stored secret.
    again = out["policies"]
    again[2]["config"]["limit"] = 20
    r = world.client.put(url, json={"policies": again}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["secrets_set"] == {jwt_id: ["secret"]}
    assert r.json()["policies"][2]["config"]["limit"] == 20

    # A new policy (no id) without a secret cannot use HS algorithms.
    no_secret = {"type": "jwt", "config": {"algorithms": ["HS256"]}}
    r = world.client.put(url, json={"policies": [no_secret]}, headers=h)
    assert r.status_code == 400 and "shared secret" in r.text

    # Audit: what changed, never the secret.
    with _db(world) as s:
        events = s.scalars(
            select(AuditEvent).where(AuditEvent.action == "api.policies.update")
        ).all()
    assert len(events) == 2
    assert all(SECRET not in (e.details or "") for e in events)
    assert f"jwt:{jwt_id}" in (events[0].details or "")


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        ({"type": "rate-limit", "routes": ["/nope"], "config": {"limit": 1}}, "unknown route"),
        (
            {
                "type": "jwt",
                "config": {"algorithms": ["RS256"], "jwks_url": "https://169.254.169.254/jwks"},
            },
            "JWKS",
        ),
        (
            {"type": "jwt", "config": {"algorithms": ["RS256"], "jwks_url": "https://127.0.0.1/"}},
            "JWKS",
        ),
        (
            {"type": "jwt", "config": {"algorithms": ["RS256"], "public_key": "-----BEGIN junk"}},
            "public key",
        ),
    ],
)
def test_policy_chain_server_side_checks(
    world: World, policy: dict[str, Any], message: str
) -> None:
    h = world.login("alice")
    pid, api = _setup(world, h)
    r = world.client.put(_chain_url(world, pid, api), json={"policies": [policy]}, headers=h)
    assert r.status_code == 400, r.text
    assert message in r.text


@pytest.mark.parametrize(
    "body",
    [
        {"policies": [{"type": "script"}]},
        {
            "policies": [
                {"type": "cors", "config": {"allow_origins": ["*"], "allow_credentials": True}}
            ]
        },
        {
            "policies": [
                {"type": "transform", "config": {"request": {"set_headers": {"host": "x"}}}}
            ]
        },
        {"policies": [{"type": "api-key", "id": "a"}, {"type": "mock", "id": "a"}]},
        {"policies": [{"type": "mock"}] * 51},
        {"policies": [], "extra": 1},
    ],
)
def test_policy_chain_validation(world: World, body: dict[str, Any]) -> None:
    h = world.login("alice")
    pid, api = _setup(world, h)
    assert world.client.put(_chain_url(world, pid, api), json=body, headers=h).status_code == 422


def test_policy_chain_rbac_and_tenant_isolation(world: World) -> None:
    alice = world.login("alice")
    pid, api = _setup(world, alice)
    url = _chain_url(world, pid, api)
    body = {"policies": [{"type": "api-key"}]}
    victor = world.login("victor")  # Viewer: policy:read only
    assert world.client.get(url, headers=victor).status_code == 200
    assert world.client.put(url, json=body, headers=victor).status_code == 403
    dev = world.login("dev")  # APIDeveloper: policy:update
    assert world.client.put(url, json=body, headers=dev).status_code == 200
    bob = world.login("bob")  # TenantAdmin of the other tenant
    assert world.client.get(url, headers=bob).status_code == 404
    assert world.client.put(url, json=body, headers=bob).status_code == 404
    # bob's own tenant path with tenant A's ids: not found either (no BOLA).
    other = _chain_url(world, pid, api, tenant=world.tenant_b)
    assert world.client.get(other, headers=bob).status_code == 404
    assert world.client.put(other, json=body, headers=bob).status_code == 404
    # An API id under the wrong product is not found.
    pid2, _ = _setup_second(world, alice)
    assert world.client.get(_chain_url(world, pid2, api), headers=alice).status_code == 404


def _setup_second(world: World, h: dict[str, str]) -> tuple[int, int]:
    base = _base(world)
    pid = world.client.post(base, json={"name": "Second"}, headers=h).json()["id"]
    return pid, 0


def test_retired_api_policies_are_read_only(world: World) -> None:
    h = world.login("alice")
    pid, api = _setup(world, h)
    lifecycle = f"{_base(world)}/{pid}/apis/{api}/lifecycle"
    for to in ("published", "deprecated", "retired"):
        assert world.client.post(lifecycle, json={"lifecycle": to}, headers=h).status_code == 200
    url = _chain_url(world, pid, api)
    r = world.client.put(url, json={"policies": []}, headers=h)
    assert r.status_code == 409


# --------------------------------------------------------------------------- API keys


def test_api_keys_shown_once_stored_hashed_and_revocable(world: World) -> None:
    h = world.login("alice")
    pid, _api = _setup(world, h)
    url = f"{_base(world)}/{pid}/api-keys"
    r = world.client.post(url, json={"name": "mobile app"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    created = r.json()
    key = created["key"]
    assert key.startswith("ak_") and len(key) > 40
    assert created["prefix"] == key[:11] and created["status"] == "active"

    listed = world.client.get(url, headers=h).json()
    assert [k["name"] for k in listed] == ["mobile app"]
    assert "key" not in listed[0] and key not in json.dumps(listed)

    with _db(world) as s:
        row = s.scalars(select(ApiKey)).one()
        assert row.key_hash == hashlib.sha256(key.encode()).hexdigest()
        assert key not in (row.key_hash, row.prefix, row.name)
        details = " ".join(e.details or "" for e in s.scalars(select(AuditEvent)))
        actions = {e.action for e in s.scalars(select(AuditEvent))}
    assert "apikey.create" in actions and key not in details

    r = world.client.post(f"{url}/{created['id']}/revoke", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert world.client.post(f"{url}/{created['id']}/revoke", headers=h).status_code == 200
    with _db(world) as s:
        revokes = s.scalars(select(AuditEvent).where(AuditEvent.action == "apikey.revoke")).all()
    assert len(revokes) == 1

    r = world.client.post(
        url, json={"name": "late", "expires_at": "2001-01-01T00:00:00Z"}, headers=h
    )
    assert r.status_code == 422
    r = world.client.post(
        url, json={"name": "naive", "expires_at": "2099-01-01T00:00:00"}, headers=h
    )
    assert r.status_code == 422
    r = world.client.post(url, json={"name": "<script>"}, headers=h)
    assert r.status_code == 422
    r = world.client.post(
        url, json={"name": "later", "expires_at": "2099-01-01T00:00:00Z"}, headers=h
    )
    assert r.status_code == 201 and r.json()["expires_at"].startswith("2099-01-01")


def test_api_key_rbac_and_tenant_isolation(world: World) -> None:
    alice = world.login("alice")
    pid, _ = _setup(world, alice)
    url = f"{_base(world)}/{pid}/api-keys"
    key_id = world.client.post(url, json={"name": "k"}, headers=alice).json()["id"]

    victor = world.login("victor")  # Viewer: apikey:read only
    assert world.client.get(url, headers=victor).status_code == 200
    assert world.client.post(url, json={"name": "v"}, headers=victor).status_code == 403
    assert world.client.post(f"{url}/{key_id}/revoke", headers=victor).status_code == 403

    dev = world.login("dev")  # APIDeveloper: apikey:manage
    assert world.client.post(url, json={"name": "d"}, headers=dev).status_code == 201

    bob = world.login("bob")
    assert world.client.get(url, headers=bob).status_code == 404
    assert world.client.post(url, json={"name": "b"}, headers=bob).status_code == 404
    assert world.client.post(f"{url}/{key_id}/revoke", headers=bob).status_code == 404
    bob_url = f"{_base(world, world.tenant_b)}/{pid}/api-keys"
    assert world.client.get(bob_url, headers=bob).status_code == 404
    assert world.client.post(f"{bob_url}/{key_id}/revoke", headers=bob).status_code == 404

    # A key id of another product is not found under this product (no BOLA).
    other = world.client.post(_base(world), json={"name": "Other"}, headers=alice).json()["id"]
    other_url = f"{_base(world)}/{other}/api-keys"
    assert world.client.post(f"{other_url}/{key_id}/revoke", headers=alice).status_code == 404
    with _db(world) as s:
        assert s.get(ApiKey, key_id).revoked_at is None
