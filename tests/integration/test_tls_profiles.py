# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""TLS profiles for upstream connections (T-023): admin API (RBAC, tenant isolation, references
in use) and the gateway connecting to a real HTTPS upstream that requires a client certificate.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import Api, Keystore, TlsProfile
from apiedge.security import x509
from apiedge.security.crypto import load_secret_box
from apiedge.security.tls import keystore_aad, server_context
from tests.integration.conftest import World, _seed
from tests.integration.test_gateway import Env, _settings
from tests.integration.test_policies_gateway import gateway
from tests.integration.test_tls import Pki, pki  # noqa: F401 - shared fixture

T = "/api/v1/tenants/{}/tls"


def _post(world: World, url: str, body: dict[str, Any], headers: dict[str, str]) -> Any:
    r = world.client.post(url, json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def test_tls_profile_crud_rbac_and_references(world: World, pki: Pki) -> None:
    c, admin, bob = world.client, world.login("alice"), world.login("bob")
    base = T.format(world.tenant_a)
    store = _post(world, base + "/truststores", {"name": "up", "certificates": pki.ca.pem()}, admin)
    ks = _post(
        world,
        base + "/keystores",
        {
            "name": "client",
            "certificate_chain": pki.client.pem(),
            "private_key": x509.private_key_pem(pki.client_key),
        },
        admin,
    )
    foreign = _post(
        world,
        T.format(world.tenant_b) + "/truststores",
        {"name": "b", "certificates": pki.ca.pem()},
        bob,
    )
    body = {"name": "backend", "truststore_id": store["id"], "keystore_id": ks["id"]}
    prof = _post(world, base + "/profiles", body, admin)
    assert prof["min_version"] == "1.2" and prof["apis"] == []
    pid = prof["id"]

    for bad in (
        {"name": "x", "truststore_id": foreign["id"]},
        {"name": "x", "keystore_id": 99999},
        {"name": "x", "ciphers": "NOSUCHCIPHER"},
    ):
        assert c.post(base + "/profiles", json=bad, headers=admin).status_code == 400, bad
    assert (
        c.post(
            base + "/profiles", json={"name": "x", "min_version": "1.1"}, headers=admin
        ).status_code
        == 422
    )
    assert (
        c.post(base + "/profiles", json={"name": "x", "ciphers": "A;B"}, headers=admin).status_code
        == 422
    )

    viewer = world.login("victor")
    assert c.get(base + f"/profiles/{pid}", headers=viewer).status_code == 200
    assert c.post(base + "/profiles", json={"name": "v"}, headers=viewer).status_code == 403
    assert (
        c.patch(base + f"/profiles/{pid}", json={"min_version": "1.3"}, headers=viewer).status_code
        == 403
    )
    assert c.get(base + f"/profiles/{pid}", headers=bob).status_code == 404
    assert c.get(T.format(world.tenant_b) + f"/profiles/{pid}", headers=bob).status_code == 404

    r = c.patch(
        base + f"/profiles/{pid}", json={"min_version": "1.3", "ciphers": None}, headers=admin
    )
    assert r.status_code == 200 and r.json()["min_version"] == "1.3"

    # An API uses the profile: profile, truststore and keystore cannot be deleted.
    prod = _post(world, f"/api/v1/tenants/{world.tenant_a}/products", {"name": "P"}, admin)["id"]
    apis = f"/api/v1/tenants/{world.tenant_a}/products/{prod}/apis"
    assert (
        c.post(
            apis, json={"name": "A", "base_path": "/a", "tls_profile_id": 99999}, headers=admin
        ).status_code
        == 400
    )
    api = _post(world, apis, {"name": "A", "base_path": "/a", "tls_profile_id": pid}, admin)
    assert api["tls_profile_id"] == pid
    assert c.get(base + f"/profiles/{pid}", headers=admin).json()["apis"] == ["A"]
    assert c.delete(base + f"/profiles/{pid}", headers=admin).status_code == 409
    assert c.delete(base + f"/truststores/{store['id']}", headers=admin).status_code == 409
    assert c.delete(base + f"/keystores/{ks['id']}", headers=admin).status_code == 409
    # A foreign tenant's API cannot point at it either.
    bprod = _post(world, f"/api/v1/tenants/{world.tenant_b}/products", {"name": "P"}, bob)["id"]
    r = c.post(
        f"/api/v1/tenants/{world.tenant_b}/products/{bprod}/apis",
        json={"name": "B", "base_path": "/b", "tls_profile_id": pid},
        headers=bob,
    )
    assert r.status_code == 400

    r = c.patch(f"{apis}/{api['id']}", json={"tls_profile_id": None}, headers=admin)
    assert r.status_code == 200 and r.json()["tls_profile_id"] is None
    assert c.delete(base + f"/profiles/{pid}", headers=admin).status_code == 204
    assert c.delete(base + f"/keystores/{ks['id']}", headers=admin).status_code == 204


# --------------------------------------------------------------------------- gateway


class TlsUpstream:
    """An HTTPS upstream that requires a client certificate issued by the test CA."""

    def __init__(self, ctx: ssl.SSLContext) -> None:
        self.ctx = ctx
        self.port = 0
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None

    async def app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"secure upstream"})

    def start(self) -> TlsUpstream:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        config = uvicorn.Config(
            self.app,
            lifespan="off",
            log_level="warning",
            interface="asgi3",
            ssl_certfile="x",
            ssl_context_factory=lambda _c, _d: self.ctx,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        assert self.server is not None and self.thread is not None
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def tls_upstream(tmp_path: Path, pki: Pki) -> Iterator[TlsUpstream]:
    cert = tmp_path / "up.pem"
    key = tmp_path / "up-key.pem"
    ca = tmp_path / "ca.pem"
    cert.write_text(pki.server.pem() + pki.ca.pem(), encoding="ascii")
    key.write_text(x509.private_key_pem(pki.server_key), encoding="ascii")
    ca.write_text(pki.ca.pem(), encoding="ascii")
    up = TlsUpstream(server_context(cert, key, client_auth="required", client_ca_file=ca)).start()
    yield up
    up.stop()


def _store(env: Env, model: Any, **fields: Any) -> int:
    with make_session_factory(make_engine(env.settings.effective_database_url))() as s:
        row = model(**fields)
        s.add(row)
        s.commit()
        return int(row.id)


def _set_profile(env: Env, api_id: int, profile_id: int | None) -> None:
    with make_session_factory(make_engine(env.settings.effective_database_url))() as s:
        api = s.get(Api, api_id)
        assert api is not None
        api.tls_profile_id = profile_id
        s.commit()


def test_gateway_uses_the_api_tls_profile(
    tmp_path: Path, pki: Pki, tls_upstream: TlsUpstream
) -> None:
    from apiedge.db.models import Truststore

    settings = _settings(tmp_path)
    a, b, _ = _seed(settings)
    env = Env(settings, a, b)
    url = f"https://127.0.0.1:{tls_upstream.port}"
    api = env.add_api("/secure", [url])
    store = _store(
        env, Truststore, tenant_id=a, name="ca", description="", certificates=pki.ca.pem()
    )
    box = load_secret_box(settings)
    assert box is not None
    ks = _store(
        env,
        Keystore,
        tenant_id=a,
        name="client",
        description="",
        certificate_chain=pki.client.pem(),
        private_key="",
        key_type="EC",
        fingerprint_sha256=pki.client.fingerprint_sha256,
        not_after=pki.client.not_after,
    )
    with make_session_factory(make_engine(settings.effective_database_url))() as s:
        row = s.get(Keystore, ks)
        assert row is not None
        row.private_key = box.encrypt(x509.private_key_pem(pki.client_key), keystore_aad(a, ks))
        s.commit()
    full = _store(
        env,
        TlsProfile,
        tenant_id=a,
        name="full",
        description="",
        min_version="1.2",
        truststore_id=store,
        keystore_id=ks,
    )
    trust_only = _store(
        env,
        TlsProfile,
        tenant_id=a,
        name="trust",
        description="",
        min_version="1.2",
        truststore_id=store,
    )

    # Default client: the test CA is unknown, the upstream is refused.
    with gateway(env) as gw:
        assert gw.get("/acme/secure/x").status_code == 502
    _set_profile(env, api, trust_only)  # trusted, but no client certificate
    with gateway(env) as gw:
        assert gw.get("/acme/secure/x").status_code == 502
    _set_profile(env, api, full)
    with gateway(env) as gw:
        r = gw.get("/acme/secure/x")
        assert r.status_code == 200 and r.text == "secure upstream", r.text

    # A key that cannot be decrypted, or a profile of another tenant: fail closed (503).
    with make_session_factory(make_engine(settings.effective_database_url))() as s:
        row = s.get(Keystore, ks)
        assert row is not None
        row.private_key = box.encrypt("garbage", keystore_aad(b, ks))
        s.commit()
    with gateway(env) as gw:
        assert gw.get("/acme/secure/x").status_code == 503
    foreign = _store(env, TlsProfile, tenant_id=b, name="b", description="", min_version="1.2")
    _set_profile(env, api, foreign)
    with gateway(env) as gw:
        assert gw.get("/acme/secure/x").status_code == 503
