# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""The LDAP client against a real OpenLDAP server (T-023, VP-010).

Runs only when ``APIEDGE_TEST_LDAP_CA`` names the CA of a running server; the CI job
``ldap-integration`` starts one in a container (pinned by digest) with these settings. Nothing
here is shipped.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from apiedge.security.ldap import (
    LdapConnection,
    LdapDirectory,
    LdapError,
    LdapResultError,
    authenticate,
)
from apiedge.security.ssrf import SsrfPolicy

CA_FILE = os.environ.get("APIEDGE_TEST_LDAP_CA", "")
PLAIN_PORT = int(os.environ.get("APIEDGE_TEST_LDAP_PORT", "10389"))
TLS_PORT = int(os.environ.get("APIEDGE_TEST_LDAPS_PORT", "10636"))
ADMIN_PASSWORD = os.environ.get("APIEDGE_TEST_LDAP_ADMIN_PASSWORD", "")
USER_PASSWORD = os.environ.get("APIEDGE_TEST_LDAP_USER_PASSWORD", "")

pytestmark = pytest.mark.skipif(not CA_FILE, reason="no OpenLDAP server configured")

ALLOW_LOCAL = SsrfPolicy(allow_private=True)
BASE = "dc=example,dc=org"
ADMIN_DN = f"cn=admin,{BASE}"


def _directory(**kw: Any) -> LdapDirectory:
    values: dict[str, Any] = {
        "host": "localhost",
        "port": PLAIN_PORT,
        "security": "plain",
        "bind_dn": ADMIN_DN,
        "bind_password": ADMIN_PASSWORD,
        "user_base_dn": BASE,
        "user_filter": "(&(objectClass=organizationalRole)(cn={username}))",
        "username_attribute": "cn",
        "timeout": 5.0,
        **kw,
    }
    return LdapDirectory(**values)


def _auth(directory: LdapDirectory, username: str, password: str) -> Any:
    return authenticate(directory, username, password, ssrf_policy=ALLOW_LOCAL)


def _ca() -> str:
    return Path(CA_FILE).read_text(encoding="ascii")


@pytest.mark.parametrize(
    "transport",
    [
        {"security": "plain", "port": PLAIN_PORT},
        {"security": "starttls", "port": PLAIN_PORT},
        {"security": "ldaps", "port": TLS_PORT},
    ],
    ids=lambda t: str(t["security"]),
)
def test_search_then_bind(transport: dict[str, Any]) -> None:
    ca = None if transport["security"] == "plain" else _ca()
    d = _directory(ca_pem=ca, **transport)
    entry = _auth(d, "readonly", USER_PASSWORD)
    assert entry is not None
    assert entry.dn == f"cn=readonly,{BASE}"
    assert entry.first("cn") == "readonly"
    assert _auth(d, "readonly", USER_PASSWORD + "x") is None
    assert _auth(d, "missing", USER_PASSWORD) is None


@pytest.mark.parametrize("username", ["*", "read*", "readonly)(cn=*", "*)(objectClass=*"])
def test_filter_injection_finds_nobody(username: str) -> None:
    assert _auth(_directory(), username, USER_PASSWORD) is None


def test_direct_bind_template_reads_the_user() -> None:
    d = _directory(user_dn_template=f"cn={{username}},{BASE}", bind_dn="", bind_password="")
    entry = _auth(d, "readonly", USER_PASSWORD)
    assert entry is not None and entry.first("cn") == "readonly"
    assert _auth(d, "readonly", "wrong") is None
    assert _auth(d, "readonly,cn=admin", USER_PASSWORD) is None


def test_wrong_service_password_is_an_error_not_a_refusal() -> None:
    with pytest.raises(LdapResultError) as caught:
        _auth(_directory(bind_password="wrong"), "readonly", USER_PASSWORD)
    assert caught.value.code == 49


def test_server_sends_many_entries_within_the_limit() -> None:
    with LdapConnection(
        "localhost", PLAIN_PORT, security="plain", ssrf_policy=ALLOW_LOCAL, timeout=5
    ) as conn:
        conn.bind(ADMIN_DN, ADMIN_PASSWORD)
        entries = conn.search(BASE, "(objectClass=*)", ["cn"], size_limit=10)
    assert {e.dn for e in entries} >= {BASE, ADMIN_DN, f"cn=readonly,{BASE}"}


@pytest.mark.parametrize("security,port", [("ldaps", TLS_PORT), ("starttls", PLAIN_PORT)])
def test_certificate_is_verified(security: str, port: int) -> None:
    with pytest.raises(LdapError, match="TLS"):  # the system store does not trust the test CA
        LdapConnection("localhost", port, security=security, ssrf_policy=ALLOW_LOCAL, timeout=5)
    with pytest.raises(LdapError, match="TLS"):  # the certificate is not for this host name
        LdapConnection(
            "127.0.0.1", port, security=security, ca_pem=_ca(), ssrf_policy=ALLOW_LOCAL, timeout=5
        )
