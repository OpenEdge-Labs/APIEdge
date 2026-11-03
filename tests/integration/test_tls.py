# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""TLS material and client certificates (T-023): truststore and keystore admin API (RBAC,
tenant isolation, encryption at rest, audit), the ``mtls`` gateway policy (through a trusted
proxy header) and native TLS listeners with real handshakes (server TLS, mTLS, TLS 1.1 refused).
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
import uvicorn
from sqlalchemy import select

from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import AuditEvent, Keystore, Truststore
from apiedge.gateway.app import create_gateway_app
from apiedge.security import x509
from apiedge.security.crypto import CryptoError, load_secret_box
from apiedge.security.tls import uvicorn_tls_options
from tests.integration.conftest import World, _seed
from tests.integration.test_gateway import (  # noqa: F401 - shared fixtures
    Env,
    Upstream,
    _clear_hits,
    _settings,
    fake_resolver,
    upstreams,
)
from tests.integration.test_policies_gateway import gateway, set_policies, upstream_headers


@dataclass(frozen=True)
class Pki:
    ca: x509.Certificate
    ca_key: Any
    other_ca: x509.Certificate
    client: x509.Certificate
    client_key: Any
    rogue: x509.Certificate  # signed by other_ca
    expired: x509.Certificate
    server_only: x509.Certificate  # no clientAuth usage
    server: x509.Certificate
    server_key: Any


@pytest.fixture(scope="module")
def pki() -> Pki:
    ca_key, other_key = x509.generate_key(), x509.generate_key()
    ca = x509.build_certificate(subject_key=ca_key, common_name="Acme CA", is_ca=True)
    other = x509.build_certificate(subject_key=other_key, common_name="Acme CA", is_ca=True)

    def leaf(cn: str, issuer: Any, key: Any, **kw: Any) -> tuple[x509.Certificate, Any]:
        k = x509.generate_key()
        return (
            x509.build_certificate(
                subject_key=k, common_name=cn, issuer=issuer, issuer_key=key, **kw
            ),
            k,
        )

    client, client_key = leaf("billing-svc", ca, ca_key, purposes=("client",))
    rogue, _ = leaf("billing-svc", other, other_key, purposes=("client",))
    expired, _ = leaf(
        "old-svc",
        ca,
        ca_key,
        purposes=("client",),
        days=1,
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
    )
    server_only, _ = leaf("web", ca, ca_key, purposes=("server",))
    server, server_key = leaf(
        "localhost",
        ca,
        ca_key,
        purposes=("server",),
        dns_names=["localhost"],
        ip_addresses=["127.0.0.1"],
    )
    return Pki(
        ca, ca_key, other, client, client_key, rogue, expired, server_only, server, server_key
    )


# --------------------------------------------------------------------------- admin API


def _base(world: World, tenant: int | None = None) -> str:
    return f"/api/v1/tenants/{tenant or world.tenant_a}/tls"


def test_truststore_crud_rbac_and_isolation(world: World, pki: Pki) -> None:
    c, admin = world.client, world.login("alice")
    base = _base(world)
    noise = "# comment that is dropped\n" + pki.ca.pem() + "trailing text\n"
    r = c.post(
        base + "/truststores", json={"name": "partners", "certificates": noise}, headers=admin
    )
    assert r.status_code == 201, r.text
    store = r.json()
    assert store["pem"] == pki.ca.pem()  # only certificates are kept, re-encoded
    [cert] = store["certificates"]
    assert cert["common_name"] == "Acme CA" and cert["is_ca"] and cert["status"] == "valid"
    assert cert["fingerprint_sha256"] == pki.ca.fingerprint_sha256
    sid = store["id"]

    assert (
        c.post(
            base + "/truststores", json={"name": "partners", "certificates": noise}, headers=admin
        ).status_code
        == 409
    )
    bad = c.post(base + "/truststores", json={"name": "x", "certificates": "nope"}, headers=admin)
    assert bad.status_code == 400 and "no PEM certificate" in bad.text
    broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    assert (
        c.post(
            base + "/truststores", json={"name": "x", "certificates": broken}, headers=admin
        ).status_code
        == 400
    )

    # Viewer reads but cannot change; another tenant's admin sees nothing.
    viewer, foreign = world.login("victor"), world.login("bob")
    assert c.get(base + f"/truststores/{sid}", headers=viewer).status_code == 200
    assert (
        c.patch(base + f"/truststores/{sid}", json={"description": "x"}, headers=viewer).status_code
        == 403
    )
    assert c.delete(base + f"/truststores/{sid}", headers=viewer).status_code == 403
    assert c.get(base + f"/truststores/{sid}", headers=foreign).status_code == 404
    other = _base(world, world.tenant_b) + f"/truststores/{sid}"
    assert c.get(other, headers=foreign).status_code == 404  # BOLA: id of tenant A in tenant B
    assert c.get(_base(world, world.tenant_b) + "/truststores", headers=foreign).json() == []

    both = pki.ca.pem() + pki.other_ca.pem()
    r = c.patch(
        base + f"/truststores/{sid}",
        json={"certificates": both, "description": "two"},
        headers=admin,
    )
    assert r.status_code == 200 and len(r.json()["certificates"]) == 2

    # In use by an mtls policy: cannot be deleted.
    prod = c.post(f"/api/v1/tenants/{world.tenant_a}/products", json={"name": "P"}, headers=admin)
    pid = prod.json()["id"]
    api = c.post(
        f"/api/v1/tenants/{world.tenant_a}/products/{pid}/apis",
        json={"name": "A", "base_path": "/a"},
        headers=admin,
    ).json()["id"]
    chain_url = f"/api/v1/tenants/{world.tenant_a}/products/{pid}/apis/{api}/policies"
    policy = {"type": "mtls", "config": {"truststore_id": sid}}
    assert c.put(chain_url, json={"policies": [policy]}, headers=admin).status_code == 200
    r = c.delete(base + f"/truststores/{sid}", headers=admin)
    assert r.status_code == 409 and "A" in r.json()["detail"]
    assert c.put(chain_url, json={"policies": []}, headers=admin).status_code == 200
    assert c.delete(base + f"/truststores/{sid}", headers=admin).status_code == 204

    with make_session_factory(make_engine(world.settings.effective_database_url))() as s:
        actions = set(
            s.scalars(select(AuditEvent.action).where(AuditEvent.tenant_id == world.tenant_a))
        )
    assert {"truststore.create", "truststore.update", "truststore.delete"} <= actions


def test_mtls_policy_must_name_a_truststore_of_the_same_tenant(world: World, pki: Pki) -> None:
    c, admin, bob = world.client, world.login("alice"), world.login("bob")
    foreign = c.post(
        _base(world, world.tenant_b) + "/truststores",
        json={"name": "b", "certificates": pki.ca.pem()},
        headers=bob,
    ).json()["id"]
    pid = c.post(
        f"/api/v1/tenants/{world.tenant_a}/products", json={"name": "P"}, headers=admin
    ).json()["id"]
    api = c.post(
        f"/api/v1/tenants/{world.tenant_a}/products/{pid}/apis",
        json={"name": "A", "base_path": "/a"},
        headers=admin,
    ).json()["id"]
    url = f"/api/v1/tenants/{world.tenant_a}/products/{pid}/apis/{api}/policies"
    for store in (foreign, 99999):
        r = c.put(
            url,
            json={"policies": [{"type": "mtls", "config": {"truststore_id": store}}]},
            headers=admin,
        )
        assert r.status_code == 400 and "truststore" in r.text
    r = c.put(
        url,
        json={
            "policies": [
                {
                    "type": "mtls",
                    "config": {"truststore_id": foreign, "forward_subject_header": "host"},
                }
            ]
        },
        headers=admin,
    )
    assert r.status_code == 422  # gateway-managed header


def test_keystore_crud_encryption_and_validation(world: World, pki: Pki) -> None:
    c, admin = world.client, world.login("alice")
    base = _base(world)
    key_pem = x509.private_key_pem(pki.client_key)
    chain = pki.client.pem() + pki.ca.pem()
    body = {"name": "client", "certificate_chain": chain, "private_key": key_pem}
    r = c.post(base + "/keystores", json=body, headers=admin)
    assert r.status_code == 201, r.text
    ks = r.json()
    assert ks["certificate"]["common_name"] == "billing-svc" and len(ks["chain"]) == 1
    assert ks["key_type"].startswith("EC")
    assert "private_key" not in ks and "PRIVATE KEY" not in r.text
    kid = ks["id"]
    listed = c.get(base + "/keystores", headers=world.login("victor"))
    assert listed.status_code == 200 and "PRIVATE" not in listed.text

    with make_session_factory(make_engine(world.settings.effective_database_url))() as s:
        row = s.get(Keystore, kid)
        assert row is not None and "PRIVATE KEY" not in row.private_key
        box = load_secret_box(world.settings)
        assert box is not None
        plain = box.decrypt_str(row.private_key, f"keystore:{world.tenant_a}:{kid}")
        assert x509.key_matches(pki.client, x509.load_private_key(plain))
        with pytest.raises(CryptoError):  # bound to tenant and keystore
            box.decrypt_str(row.private_key, f"keystore:{world.tenant_b}:{kid}")

    wrong = {**body, "name": "wrong", "private_key": x509.private_key_pem(pki.server_key)}
    r = c.post(base + "/keystores", json=wrong, headers=admin)
    assert r.status_code == 400 and "does not belong" in r.text
    junk = {**body, "name": "junk", "private_key": "-----BEGIN PRIVATE KEY-----\nAA\n"}
    assert c.post(base + "/keystores", json=junk, headers=admin).status_code == 400
    public = {
        **body,
        "name": "pub",
        "private_key": pki.client_key.public_key().export_key(format="PEM"),
    }
    assert c.post(base + "/keystores", json=public, headers=admin).status_code == 400

    # Encrypted private key with passphrase.
    enc = pki.client_key.export_key(
        format="PEM", passphrase="s3cret-pass", protection="PBKDF2WithHMAC-SHA512AndAES256-CBC"
    )
    with_pass = {**body, "name": "enc", "private_key": enc}
    assert c.post(base + "/keystores", json=with_pass, headers=admin).status_code == 400
    with_pass["passphrase"] = "s3cret-pass"
    assert c.post(base + "/keystores", json=with_pass, headers=admin).status_code == 201

    dev, bob = world.login("dev"), world.login("bob")
    assert c.post(base + "/keystores", json={**body, "name": "d"}, headers=dev).status_code == 403
    assert c.delete(base + f"/keystores/{kid}", headers=dev).status_code == 403
    assert c.get(base + f"/keystores/{kid}", headers=bob).status_code == 404
    assert c.delete(base + f"/keystores/{kid}", headers=bob).status_code == 404
    assert c.delete(base + f"/keystores/{kid}", headers=admin).status_code == 204
    assert c.get(base + f"/keystores/{kid}", headers=admin).status_code == 404


# --------------------------------------------------------------------------- mtls policy

PROXY = ("10.0.0.5", 40000)
HEADER = "x-client-cert"


@pytest.fixture
def env(tmp_path: Path) -> Env:
    settings = _settings(
        tmp_path, gateway_trusted_proxies=["10.0.0.0/8"], gateway_client_cert_header=HEADER
    )
    a, b, _users = _seed(settings)
    return Env(settings, a, b)


def _truststore(env: Env, tenant: int, *certs: x509.Certificate) -> int:
    with make_session_factory(make_engine(env.settings.effective_database_url))() as s:
        t = Truststore(
            tenant_id=tenant,
            name=f"ts{time.monotonic_ns()}",
            description="",
            certificates=x509.bundle_pem(certs),
        )
        s.add(t)
        s.commit()
        return t.id


def _cert_header(cert: x509.Certificate) -> dict[str, str]:
    return {HEADER: quote(cert.pem())}


def test_mtls_policy(env: Env, upstreams: dict[str, Upstream], pki: Pki) -> None:
    api = env.add_api("/pay", [upstreams["a"].url])
    store = _truststore(env, env.tenant_a, pki.ca)
    set_policies(
        env,
        api,
        [
            {
                "type": "mtls",
                "config": {"truststore_id": store, "forward_subject_header": "x-client-subject"},
            }
        ],
    )
    with gateway(env, client=PROXY) as gw:
        assert gw.get("/acme/pay/x").status_code == 401  # no certificate
        ok = gw.get(
            "/acme/pay/x", headers={**_cert_header(pki.client), "x-client-subject": "CN=forged"}
        )
        assert ok.status_code == 200, ok.text
        seen = upstream_headers(ok)
        assert seen["x-client-subject"] == "CN=billing-svc"
        assert HEADER not in seen  # the forwarded certificate never reaches the upstream
        for bad in (pki.rogue, pki.expired, pki.server_only):
            r = gw.get("/acme/pay/x", headers=_cert_header(bad))
            assert r.status_code == 401, bad.common_name
        assert gw.get("/acme/pay/x", headers={HEADER: "garbage"}).status_code == 401
    # The header is ignored from a client that is not a trusted proxy.
    with gateway(env) as direct:
        r = direct.get("/acme/pay/x", headers=_cert_header(pki.client))
        assert r.status_code == 401


def test_mtls_allow_lists_and_fail_closed(
    env: Env, upstreams: dict[str, Upstream], pki: Pki
) -> None:
    api = env.add_api("/pay", [upstreams["a"].url])
    store = _truststore(env, env.tenant_a, pki.ca)
    set_policies(
        env,
        api,
        [
            {
                "type": "mtls",
                "config": {
                    "truststore_id": store,
                    "allowed_fingerprints": [pki.server.fingerprint_sha256],
                },
            }
        ],
    )
    with gateway(env, client=PROXY) as gw:
        assert gw.get("/acme/pay/x", headers=_cert_header(pki.client)).status_code == 403
    set_policies(
        env,
        api,
        [{"type": "mtls", "config": {"truststore_id": store, "allowed_subjects": ["billing-svc"]}}],
    )
    with gateway(env, client=PROXY) as gw:
        assert gw.get("/acme/pay/x", headers=_cert_header(pki.client)).status_code == 200
    # Pinned leaf: a truststore holding the client certificate itself.
    pinned = _truststore(env, env.tenant_a, pki.client)
    set_policies(env, api, [{"type": "mtls", "config": {"truststore_id": pinned}}])
    with gateway(env, client=PROXY) as gw:
        assert gw.get("/acme/pay/x", headers=_cert_header(pki.client)).status_code == 200
        assert gw.get("/acme/pay/x", headers=_cert_header(pki.expired)).status_code == 401
    # A truststore of another tenant (hand-edited row) is never used: the policy fails closed.
    foreign = _truststore(env, env.tenant_b, pki.ca)
    set_policies(env, api, [{"type": "mtls", "config": {"truststore_id": foreign}}])
    with gateway(env, client=PROXY) as gw:
        assert gw.get("/acme/pay/x", headers=_cert_header(pki.client)).status_code == 503


# --------------------------------------------------------------------------- native TLS


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="ascii")
    return path


@pytest.fixture
def tls_files(tmp_path: Path, pki: Pki) -> dict[str, Path]:
    return {
        "cert": _write(tmp_path / "server.pem", pki.server.pem() + pki.ca.pem()),
        "key": _write(tmp_path / "server-key.pem", x509.private_key_pem(pki.server_key)),
        "ca": _write(tmp_path / "ca.pem", pki.ca.pem()),
        "client": _write(tmp_path / "client.pem", pki.client.pem()),
        "client_key": _write(tmp_path / "client-key.pem", x509.private_key_pem(pki.client_key)),
    }


@pytest.fixture
def tls_gateway(
    tmp_path: Path, tls_files: dict[str, Path], upstreams: dict[str, Upstream], pki: Pki
) -> Iterator[tuple[int, Env]]:
    settings = _settings(
        tmp_path,
        gateway_tls_cert_file=tls_files["cert"],
        gateway_tls_key_file=tls_files["key"],
        gateway_tls_client_auth="optional",
        gateway_tls_client_ca_file=tls_files["ca"],
    )
    a, b, _ = _seed(settings)
    env = Env(settings, a, b)
    api = env.add_api("/pay", [upstreams["a"].url])
    set_policies(
        env, api, [{"type": "mtls", "config": {"truststore_id": _truststore(env, a, pki.ca)}}]
    )
    app = create_gateway_app(settings, None, resolver=fake_resolver)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, log_level="warning", **uvicorn_tls_options(settings, gateway=True))
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline, "TLS gateway did not start"
        time.sleep(0.02)
    yield port, env
    server.should_exit = True
    thread.join(timeout=10)


def _ctx(tls_files: dict[str, Path], *, client: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(tls_files["ca"]))
    if client:
        ctx.load_cert_chain(str(tls_files["client"]), str(tls_files["client_key"]))
    return ctx


def test_native_tls_gateway_with_client_certificates(
    tls_gateway: tuple[int, Env], tls_files: dict[str, Path]
) -> None:
    port, _env = tls_gateway
    url = f"https://localhost:{port}/acme/pay/x"
    with httpx.Client(verify=_ctx(tls_files, client=True)) as c:
        r = c.get(url)
        assert r.status_code == 200, r.text
        assert r.json()["upstream"] == "a"
    with httpx.Client(verify=_ctx(tls_files, client=False)) as c:
        assert c.get(url).status_code == 401  # optional at the handshake, required by the policy
    plain_refused = (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError)
    with pytest.raises(plain_refused):  # plain HTTP is not served on a TLS listener
        httpx.get(f"http://localhost:{port}/acme/pay/x", timeout=5).raise_for_status()
    old = _ctx(tls_files, client=True)
    old.minimum_version = old.maximum_version = ssl.TLSVersion.TLSv1_1
    with pytest.raises(httpx.ConnectError), httpx.Client(verify=old) as c:
        c.get(url)


def test_required_client_certificates_fail_the_handshake(
    tmp_path: Path, tls_files: dict[str, Path]
) -> None:
    from apiedge.security.tls import server_context

    ctx = server_context(
        tls_files["cert"],
        tls_files["key"],
        min_version="1.3",
        client_auth="required",
        client_ca_file=tls_files["ca"],
    )
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        log_level="critical",
        lifespan="off",
        ssl_certfile="x",
        ssl_context_factory=lambda _c, _d: ctx,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline
        time.sleep(0.02)
    try:
        with httpx.Client(verify=_ctx(tls_files, client=True)) as c:
            assert c.get(f"https://localhost:{port}/").status_code == 204
        refused = (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)
        with pytest.raises(refused), httpx.Client(verify=_ctx(tls_files, client=False)) as c:
            c.get(f"https://localhost:{port}/")
    finally:
        server.should_exit = True
        thread.join(timeout=10)
