# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""LDAP directories (T-023): admin API (RBAC, tenant isolation, secrets, redirection guard) and
the ``basic-ldap`` policy in the gateway against a directory server on a real socket.
"""

from __future__ import annotations

import base64
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from apiedge.db.base import make_engine, make_session_factory
from apiedge.db.models import AuditEvent, LdapDirectory
from apiedge.security import ldap, x509
from apiedge.security.crypto import load_secret_box
from tests.integration.conftest import World, _seed
from tests.integration.test_gateway import (  # noqa: F401 - shared fixtures
    Env,
    Upstream,
    _settings,
    upstreams,
)
from tests.integration.test_policies_gateway import gateway, set_policies, upstream_headers
from tests.unit.test_ldap import SERVICE, directory_handler

PUBLIC_IP = "93.184.216.34"  # a literal needs no DNS and passes the default SSRF policy
FILTER = "(&(objectClass=person)(uid={username}))"
USER_BASE = "ou=people,dc=example,dc=com"


# --------------------------------------------------------------------------- admin API


def _base(tenant_id: int) -> str:
    return f"/api/v1/tenants/{tenant_id}/ldap/directories"


def _body(**kw: Any) -> dict[str, Any]:
    return {"name": "corp", "host": PUBLIC_IP, "user_base_dn": USER_BASE, **kw}


def _create(world: World, headers: dict[str, str], **kw: Any) -> dict[str, Any]:
    r = world.client.post(_base(world.tenant_a), json=_body(**kw), headers=headers)
    assert r.status_code == 201, r.text
    out: dict[str, Any] = r.json()
    return out


def test_directory_crud_rbac_and_tenant_isolation(world: World) -> None:
    c, admin, bob, viewer = (
        world.client,
        world.login("alice"),
        world.login("bob"),
        world.login("victor"),
    )
    base = _base(world.tenant_a)
    d = _create(world, admin, description="main")
    assert d["security"] == "ldaps" and d["port"] == 636 and d["bind_password_set"] is False
    url = f"{base}/{d['id']}"

    assert c.get(url, headers=viewer).status_code == 200
    assert c.post(base, json=_body(name="v"), headers=viewer).status_code == 403
    assert c.patch(url, json={"port": 1636}, headers=viewer).status_code == 403
    assert c.delete(url, headers=viewer).status_code == 403
    assert c.post(url + "/test", headers=viewer).status_code == 403
    assert c.get(url, headers=bob).status_code == 404
    assert c.get(f"{_base(world.tenant_b)}/{d['id']}", headers=bob).status_code == 404

    assert c.post(base, json=_body(), headers=admin).status_code == 409  # same name
    r = c.patch(url, json={"port": 1636, "description": "new"}, headers=admin)
    assert r.status_code == 200 and r.json()["port"] == 1636
    assert c.delete(url, headers=admin).status_code == 204
    assert c.get(url, headers=admin).status_code == 404


@pytest.mark.parametrize(
    "bad",
    [
        {"user_filter": "(uid=fixed)"},  # no {username}
        {"user_filter": "(uid={username}"},  # malformed
        {"user_dn_template": "uid=fixed,dc=x"},
        {"security": "none"},
        {"port": 0},
        {"host": "-bad host"},
        {"bind_dn": "cn=a\nb"},
        {"username_attribute": "a b"},
    ],
)
def test_invalid_fields_are_refused(world: World, bad: dict[str, Any]) -> None:
    r = world.client.post(_base(world.tenant_a), json=_body(**bad), headers=world.login("alice"))
    assert r.status_code == 422, r.text


@pytest.mark.parametrize(
    "bad",
    [
        {"host": "127.0.0.1"},  # SSRF guard
        {"host": "169.254.169.254"},
        {"bind_dn": "cn=svc,dc=x"},  # service account without a password
        {"bind_password": "secret"},  # password without a service account
        {"user_base_dn": ""},  # neither search base nor template
        {"truststore_id": 999999},
    ],
)
def test_inconsistent_or_unsafe_directories_are_refused(world: World, bad: dict[str, Any]) -> None:
    r = world.client.post(_base(world.tenant_a), json=_body(**bad), headers=world.login("alice"))
    assert r.status_code == 400, r.text


def test_service_password_is_encrypted_write_only_and_audited(world: World) -> None:
    admin = world.login("alice")
    d = _create(world, admin, bind_dn="cn=svc,dc=x", bind_password="S3rvice-Secret")
    assert d["bind_password_set"] is True
    assert "S3rvice-Secret" not in str(d) and "bind_password" not in d

    engine = make_engine(world.settings.effective_database_url)
    with make_session_factory(engine)() as s:
        token = s.scalars(select(LdapDirectory.bind_password)).one()
        logged = [str(a.details) for a in s.scalars(select(AuditEvent))]
    engine.dispose()
    assert token and "S3rvice-Secret" not in token
    box = load_secret_box(world.settings)
    assert box is not None
    aad = ldap.bind_password_aad(world.tenant_a, d["id"])
    assert box.decrypt_str(token, aad) == "S3rvice-Secret"
    assert not any("S3rvice-Secret" in row for row in logged)
    assert any("corp" in row for row in logged)


@pytest.mark.parametrize(
    "change",
    [{"host": "93.184.216.35"}, {"port": 1636}, {"security": "starttls"}],
)
def test_stored_password_cannot_be_redirected(world: World, change: dict[str, Any]) -> None:
    """Whoever can edit a directory must not get the stored password sent to their own server."""
    c, admin = world.client, world.login("alice")
    d = _create(world, admin, bind_dn="cn=svc,dc=x", bind_password="S3rvice-Secret")
    url = f"{_base(world.tenant_a)}/{d['id']}"
    assert c.patch(url, json=change, headers=admin).status_code == 400
    assert c.get(url, headers=admin).json()["host"] == PUBLIC_IP
    # Sending the unchanged value is not a change; other fields need no password.
    assert c.patch(url, json={"host": PUBLIC_IP}, headers=admin).status_code == 200
    assert c.patch(url, json={"user_base_dn": "dc=y"}, headers=admin).status_code == 200
    # Re-entering the password allows it, and removing the account clears the password.
    assert c.patch(url, json={**change, "bind_password": "new"}, headers=admin).status_code == 200
    cleared = c.patch(url, json={"bind_dn": ""}, headers=admin)
    assert cleared.status_code == 200 and cleared.json()["bind_password_set"] is False


def test_references_to_truststores_and_directories(world: World) -> None:
    c, admin, bob = world.client, world.login("alice"), world.login("bob")
    tid = world.tenant_a
    key = x509.generate_key()
    ca = x509.build_certificate(subject_key=key, common_name="CA", is_ca=True)
    tls = f"/api/v1/tenants/{tid}/tls/truststores"
    store = c.post(tls, json={"name": "ca", "certificates": ca.pem()}, headers=admin).json()["id"]
    foreign = c.post(
        f"/api/v1/tenants/{world.tenant_b}/tls/truststores",
        json={"name": "b", "certificates": ca.pem()},
        headers=bob,
    ).json()["id"]
    bad = c.post(_base(tid), json=_body(truststore_id=foreign), headers=admin)
    assert bad.status_code == 400
    d = _create(world, admin, truststore_id=store)
    assert c.delete(f"{tls}/{store}", headers=admin).status_code == 409

    base = f"/api/v1/tenants/{tid}/products"
    product = c.post(base, json={"name": "P"}, headers=admin).json()["id"]
    api = c.post(
        f"{base}/{product}/apis", json={"name": "A", "base_path": "/a"}, headers=admin
    ).json()["id"]
    chain = f"{base}/{product}/apis/{api}/policies"

    def policy(directory: int) -> dict[str, Any]:
        return {"policies": [{"type": "basic-ldap", "config": {"directory_id": directory}}]}

    other = c.post(_base(world.tenant_b), json=_body(name="b"), headers=bob).json()["id"]
    assert c.put(chain, json=policy(other), headers=admin).status_code == 400  # other tenant
    assert c.put(chain, json=policy(999999), headers=admin).status_code == 400
    assert c.put(chain, json=policy(d["id"]), headers=admin).status_code == 200

    url = f"{_base(tid)}/{d['id']}"
    assert c.get(url, headers=admin).json()["apis"] == ["A"]
    assert c.delete(url, headers=admin).status_code == 409
    assert c.put(chain, json={"policies": []}, headers=admin).status_code == 200
    assert c.delete(url, headers=admin).status_code == 204
    assert c.delete(f"{tls}/{store}", headers=admin).status_code == 204


def test_connection_test_reports_without_leaking(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, admin = world.client, world.login("alice")
    d = _create(world, admin, bind_dn="cn=svc,dc=x", bind_password="S3rvice-Secret")
    url = f"{_base(world.tenant_a)}/{d['id']}/test"
    seen: list[ldap.LdapDirectory] = []

    def works(directory: ldap.LdapDirectory, **_kw: Any) -> None:
        seen.append(directory)

    monkeypatch.setattr(ldap, "check_directory", works)
    r = c.post(url, headers=admin)
    assert r.status_code == 200 and r.json() == {"ok": True, "message": "Connected."}
    assert seen[0].bind_password == "S3rvice-Secret" and seen[0].timeout == 5.0

    def fails(_directory: ldap.LdapDirectory, **_kw: Any) -> None:
        raise ldap.LdapResultError(49, "invalid credentials")

    monkeypatch.setattr(ldap, "check_directory", fails)
    r = c.post(url, headers=admin)
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "49" in r.json()["message"] and "S3rvice-Secret" not in r.text


# --------------------------------------------------------------------------- gateway


class DirectoryServer:
    """A directory on a real TCP socket, answering with the unit tests' protocol handler."""

    def __init__(self) -> None:
        self.user_binds: list[str] = []
        self.connections = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port: int = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv(conn: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            while True:
                head = self._recv(conn, 2)
                if head is None:
                    return
                extra = b""
                size = head[1]
                if size & 0x80:
                    extra = self._recv(conn, size & 0x7F) or b""
                    size = int.from_bytes(extra, "big")
                msg = ldap.decode(head + extra + (self._recv(conn, size) or b""))
                mid = int.from_bytes(msg.children[0].value, "big")
                op = msg.children[1]
                if op.tag == 0x42:  # unbind
                    return
                if op.tag == 0x60 and op.children[1].value.decode() != SERVICE[0]:
                    self.user_binds.append(op.children[1].value.decode())
                for chunk in directory_handler(mid, op):
                    conn.sendall(chunk)

    def close(self) -> None:
        self.listener.close()


@pytest.fixture
def directory_server() -> Iterator[DirectoryServer]:
    server = DirectoryServer()
    yield server
    server.close()


@pytest.fixture
def env(tmp_path: Path) -> Env:
    settings = _settings(tmp_path)
    a, b, _users = _seed(settings)
    return Env(settings, a, b)


def _add_directory(env: Env, tenant_id: int, host: str, port: int) -> int:
    box = load_secret_box(env.settings)
    assert box is not None
    engine = make_engine(env.settings.effective_database_url)
    with make_session_factory(engine)() as s:
        d = LdapDirectory(
            tenant_id=tenant_id,
            name=f"d{port}",
            host=host,
            port=port,
            security="plain",
            bind_dn=SERVICE[0],
            user_base_dn=USER_BASE,
            user_filter=FILTER,
        )
        s.add(d)
        s.flush()
        d.bind_password = box.encrypt(SERVICE[1], ldap.bind_password_aad(tenant_id, d.id))
        s.commit()
        out = d.id
    engine.dispose()
    return out


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"authorization": f"Basic {token}"}


ALICE = _basic("alice", "Wonder-Land-1")


def test_basic_ldap_policy(
    env: Env,
    upstreams: dict[str, Upstream],  # noqa: F811
    directory_server: DirectoryServer,
) -> None:
    api = env.add_api("/pay", [upstreams["a"].url])
    d = _add_directory(env, env.tenant_a, "127.0.0.1", directory_server.port)
    config = {"directory_id": d, "realm": "Payments", "forward_user_header": "x-user"}
    set_policies(env, api, [{"type": "basic-ldap", "config": config}])
    with gateway(env) as gw:
        r = gw.get("/acme/pay/x")
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == 'Basic realm="Payments", charset="UTF-8"'
        for bad in (
            {"authorization": "Bearer abc"},
            {"authorization": "Basic not base64!"},
            {"authorization": "Basic " + base64.b64encode(b"no-colon").decode()},
            {"authorization": "Basic " + base64.b64encode(b"alice:").decode()},
            {"authorization": "Basic " + base64.b64encode(b"\xff\xfe:x").decode()},
        ):
            assert gw.get("/acme/pay/x", headers=bad).status_code == 401, bad
        assert directory_server.connections == 0  # malformed input never reaches the directory

        ok = gw.get("/acme/pay/x", headers={**ALICE, "x-user": "forged"})
        assert ok.status_code == 200, ok.text
        seen = upstream_headers(ok)
        assert seen["x-user"] == "alice"
        assert "authorization" not in seen  # credentials stay at the gateway

        assert gw.get("/acme/pay/x", headers=_basic("alice", "wrong")).status_code == 401
        assert gw.get("/acme/pay/x", headers=_basic("nobody", "x")).status_code == 401
        injected = _basic("*)(uid=*", "Wonder-Land-1")
        assert gw.get("/acme/pay/x", headers=injected).status_code == 401


def test_results_are_remembered_only_as_configured(
    env: Env,
    upstreams: dict[str, Upstream],  # noqa: F811
    directory_server: DirectoryServer,
) -> None:
    api = env.add_api("/pay", [upstreams["a"].url])
    d = _add_directory(env, env.tenant_a, "127.0.0.1", directory_server.port)
    set_policies(env, api, [{"type": "basic-ldap", "config": {"directory_id": d}}])
    wrong = _basic("alice", "wrong")
    with gateway(env) as gw:
        for _ in range(3):
            assert gw.get("/acme/pay/x", headers=ALICE).status_code == 200
            assert gw.get("/acme/pay/x", headers=wrong).status_code == 401
    # One check each: repeating a wrong password cannot lock the account in the directory.
    assert len(directory_server.user_binds) == 2

    directory_server.user_binds.clear()
    config = {"directory_id": d, "cache_seconds": 0, "hide_credentials": False}
    set_policies(env, api, [{"type": "basic-ldap", "config": config}])
    with gateway(env) as gw:
        for _ in range(2):
            r = gw.get("/acme/pay/x", headers=ALICE)
            assert r.status_code == 200
            assert "authorization" in upstream_headers(r)  # kept when asked for
    assert len(directory_server.user_binds) == 2


def test_policy_fails_closed(
    env: Env,
    upstreams: dict[str, Upstream],  # noqa: F811
    directory_server: DirectoryServer,
) -> None:
    api = env.add_api("/pay", [upstreams["a"].url])

    def status(directory_id: int) -> int:
        set_policies(env, api, [{"type": "basic-ldap", "config": {"directory_id": directory_id}}])
        with gateway(env) as gw:
            return int(gw.get("/acme/pay/x", headers=ALICE).status_code)

    # The directory is down.
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    assert status(_add_directory(env, env.tenant_a, "127.0.0.1", closed_port)) == 503
    # The SSRF guard is applied when connecting, not only when saving.
    assert status(_add_directory(env, env.tenant_a, "10.1.2.3", directory_server.port)) == 503
    # Another tenant's directory and one that no longer exists.
    foreign = _add_directory(env, env.tenant_b, "127.0.0.1", directory_server.port + 1)
    assert status(foreign) == 503
    assert status(999999) == 503
    # A password that cannot be decrypted.
    broken = _add_directory(env, env.tenant_a, "127.0.0.1", directory_server.port + 2)
    engine = make_engine(env.settings.effective_database_url)
    with make_session_factory(engine)() as s:
        row = s.get(LdapDirectory, broken)
        assert row is not None
        row.bind_password = "not-a-token"
        s.commit()
    engine.dispose()
    assert status(broken) == 503
    assert directory_server.connections == 0
