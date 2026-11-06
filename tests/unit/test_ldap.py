# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""The minimal LDAPv3 client (T-023 slice 3, VP-010): BER, filters, escaping, protocol, TLS."""

from __future__ import annotations

import contextlib
import random
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from apiedge.security import ldap
from apiedge.security import x509 as x
from apiedge.security.ldap import (
    Element,
    LdapConnection,
    LdapDirectory,
    LdapError,
    LdapResultError,
    authenticate,
    ber_int,
    ber_seq,
    ber_str,
    decode,
    escape_dn_value,
    escape_filter_value,
    fill_template,
    parse_filter,
    tlv,
)
from apiedge.security.ssrf import SsrfPolicy

# --------------------------------------------------------------------------- BER


def test_ber_roundtrip_and_long_lengths() -> None:
    blob = ber_seq(ber_int(7), ber_str("x" * 300), ber_int(-129))
    e = decode(blob)
    assert e.tag == 0x30 and len(e.children) == 3
    assert e.children[1].value == b"x" * 300
    assert int.from_bytes(e.children[2].value, "big", signed=True) == -129
    # Active Directory always uses 4-byte lengths; non-minimal long forms are accepted.
    assert decode(b"\x04\x84\x00\x00\x00\x02hi").value == b"hi"


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x30",
        b"\x30\x80\x00\x00",  # indefinite length
        b"\x1f\x01\x00",  # high tag number
        b"\x04\x85\x00\x00\x00\x00\x01x",  # 5-byte length field
        b"\x04\x05abc",  # length past the end
        b"\x30\x03\x04\x05a",  # child longer than its parent
        b"\x04\x01ab",  # trailing bytes
        b"\x04\x84\xff\xff\xff\xff",  # 4 GiB claimed
    ],
)
def test_ber_rejects_malformed(blob: bytes) -> None:
    with pytest.raises(LdapError):
        decode(blob)


def test_ber_depth_and_element_limits() -> None:
    deep = b"\x05\x00"
    for _ in range(ldap.MAX_DEPTH + 2):
        deep = tlv(0x30, deep)
    with pytest.raises(LdapError, match="deep"):
        decode(deep)
    many = tlv(0x30, b"\x05\x00" * (ldap.MAX_ELEMENTS + 1))
    with pytest.raises(LdapError, match="too many"):
        decode(many)


def test_ber_fuzz_only_raises_ldap_error() -> None:
    """Random and mutated input never crashes the decoder with anything but LdapError."""
    rnd = random.Random(4511)  # noqa: S311 - deterministic fuzzing, not cryptography
    valid = [
        _result(1, 0x61, 0),
        _entry_msg(2, "uid=a,dc=x", {"mail": ["a@x"], "cn": ["A"]}),
        ber_seq(ber_int(5), parse_filter("(&(a=b)(!(c=*))(d=x*y*z))")),
    ]
    for i in range(6000):
        if i % 3 == 0:
            data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 64)))
        else:
            mutated = bytearray(rnd.choice(valid))
            for _ in range(rnd.randrange(1, 4)):
                mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
            data = bytes(mutated[: rnd.randrange(1, len(mutated) + 1)])
        with contextlib.suppress(LdapError):
            decode(data)


# --------------------------------------------------------------------------- filters / escaping


def test_filter_encoding() -> None:
    assert parse_filter("(uid=alice)") == ber_seq(ber_str("uid"), ber_str("alice"), tag=0xA3)
    assert parse_filter("(mail=*)") == tlv(0x87, b"mail")
    sub = parse_filter("(cn=a*b*c)")
    assert sub == ber_seq(
        ber_str("cn"),
        ber_seq(ber_str("a", 0x80), ber_str("b", 0x81), ber_str("c", 0x82)),
        tag=0xA4,
    )
    assert parse_filter("(age>=21)")[0] == 0xA5
    assert parse_filter("(age<=21)")[0] == 0xA6
    assert parse_filter("(cn~=bob)")[0] == 0xA8
    ad = parse_filter("(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
    assert ad[0] == 0xA0
    assert b"1.2.840.113556.1.4.803" in ad
    assert parse_filter("(cn=a\\2ab)") == ber_seq(ber_str("cn"), ber_str("a*b"), tag=0xA3)
    assert parse_filter("(cn=x=y)") == ber_seq(ber_str("cn"), ber_str("x=y"), tag=0xA3)


@pytest.mark.parametrize(
    "text",
    [
        "uid=a",
        "(uid=a",
        "(uid=a))",
        "()",
        "(&)",
        "(=a)",
        "(uid)",
        "(u id=a)",
        "(uid=a\\zz)",
        "(uid=a\\2)",
        "(cn=a**b)",
        "(uid=a)(uid=b)",
        "(:=x)",
        "(cn:a:b:=x)",
        "(" * 20 + "a=b" + ")" * 20,
        "(&" + "(a=b)" * 2000 + ")",
    ],
)
def test_filter_rejects_malformed(text: str) -> None:
    with pytest.raises(LdapError):
        parse_filter(text)


@pytest.mark.parametrize(
    "attack",
    [
        "*",
        "*)(uid=*",
        "admin)(|(uid=*",
        "a*)(objectClass=*))(&(uid=a",
        "\\",
        "x\x00y",
        "*))%00",
    ],
)
def test_filter_injection_is_neutralised(attack: str) -> None:
    """An escaped value is one equality assertion holding the literal input, whatever it is."""
    text = fill_template(
        "(&(objectClass=person)(uid={username}))", username=escape_filter_value(attack)
    )
    encoded = parse_filter(text)
    and_set = decode(encoded)
    assert and_set.tag == 0xA0 and len(and_set.children) == 2
    eq = and_set.children[1]
    assert eq.tag == 0xA3
    assert eq.children[1].value == attack.encode("utf-8")


def test_escape_values() -> None:
    assert escape_filter_value("a*(b)\\\x00") == "a\\2a\\28b\\29\\5c\\00"
    assert escape_dn_value("Smith, John+x") == "Smith\\, John\\+x"
    assert escape_dn_value("#a ") == "\\#a\\ "
    assert escape_dn_value(" a=b") == "\\ a\\=b"
    assert fill_template("uid={username},dc=x", username="{username}") == "uid={username},dc=x"


# --------------------------------------------------------------------------- fake server


def _result(mid: int, tag: int, code: int, message: str = "") -> bytes:
    body = ber_int(code, 0x0A) + ber_str("") + ber_str(message)
    return ber_seq(ber_int(mid), tlv(tag, body))


def _entry_msg(mid: int, dn: str, attrs: dict[str, list[str]]) -> bytes:
    attr_seq = b"".join(
        ber_seq(ber_str(k), tlv(0x31, b"".join(ber_str(v) for v in vals)))
        for k, vals in attrs.items()
    )
    return ber_seq(ber_int(mid), ber_seq(ber_str(dn), ber_seq(attr_seq), tag=0x64))


Handler = Callable[[int, Element], list[bytes]]


class FakeServer:
    """Answers LDAP requests on one end of a socket pair, from a handler function."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[Element] = []
        self.client, self.server = socket.socketpair()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def connector(self, _address: str, _port: int, _timeout: float) -> socket.socket:
        return self.client

    def _read(self) -> bytes | None:
        head = self._recv(2)
        if head is None:
            return None
        extra = b""
        if head[1] & 0x80:
            extra = self._recv(head[1] & 0x7F) or b""
            size = int.from_bytes(extra, "big")
        else:
            size = head[1]
        return head + extra + (self._recv(size) or b"")

    def _recv(self, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = self.server.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _run(self) -> None:
        try:
            while True:
                raw = self._read()
                if raw is None:
                    return
                msg = decode(raw)
                mid = int.from_bytes(msg.children[0].value, "big")
                op = msg.children[1]
                self.requests.append(op)
                if op.tag == 0x42:
                    return
                for chunk in self.handler(mid, op):
                    if chunk == b"SLEEP":
                        time.sleep(1.5)
                        continue
                    self.server.sendall(chunk)
        except OSError:
            return
        finally:
            self.server.close()


USERS = {"uid=alice,ou=people,dc=example,dc=com": "Wonder-Land-1"}
SERVICE = ("cn=svc,dc=example,dc=com", "svc-pass")


def directory_handler(mid: int, op: Element) -> list[bytes]:
    if op.tag == 0x60:  # bind
        dn = op.children[1].value.decode()
        pw = op.children[2].value.decode()
        ok = (dn, pw) == SERVICE or USERS.get(dn) == pw
        return [_result(mid, 0x61, 0 if ok else 49, "" if ok else "invalid credentials")]
    if op.tag == 0x63:  # search
        filt = op.children[6]  # (&(objectClass=person)(uid=<value>))
        value = filt.children[1].children[1].value if filt.tag == 0xA0 else b""
        out = []
        if value == b"alice":
            out.append(
                _entry_msg(mid, "uid=alice,ou=people,dc=example,dc=com", {"mail": ["a@x.io"]})
            )
        if value == b"twin":
            out += [_entry_msg(mid, f"uid=twin{i},dc=x", {}) for i in range(2)]
        out.append(_result(mid, 0x65, 0))
        return out
    return [_result(mid, 0x78, 2, "unsupported")]


DIRECTORY = LdapDirectory(
    host="ldap.example.com",
    port=389,
    security="plain",
    bind_dn=SERVICE[0],
    bind_password=SERVICE[1],
    user_base_dn="ou=people,dc=example,dc=com",
    user_filter="(&(objectClass=person)(uid={username}))",
)


def _auth(handler: Handler, username: str, password: str, **kw: Any) -> tuple[Any, FakeServer]:
    srv = FakeServer(handler)
    d = LdapDirectory(**{**DIRECTORY.__dict__, **kw})
    result = authenticate(d, username, password, connector=srv.connector, addresses=["192.0.2.1"])
    return result, srv


def test_search_then_bind() -> None:
    entry, srv = _auth(directory_handler, "alice", "Wonder-Land-1")
    assert entry is not None and entry.first("mail") == "a@x.io"
    assert [r.tag for r in srv.requests] == [0x60, 0x63, 0x60, 0x42]


def test_wrong_password_unknown_and_ambiguous_users() -> None:
    assert _auth(directory_handler, "alice", "nope")[0] is None
    assert _auth(directory_handler, "bob", "Wonder-Land-1")[0] is None
    assert _auth(directory_handler, "twin", "x")[0] is None


def test_empty_password_never_reaches_the_server() -> None:
    entry, srv = _auth(directory_handler, "alice", "")
    assert entry is None and srv.requests == []
    with pytest.raises(LdapError, match="empty"):
        srv2 = FakeServer(directory_handler)
        LdapConnection("h", 389, security="plain", addresses=["1"], connector=srv2.connector).bind(
            "uid=alice", ""
        )


@pytest.mark.parametrize("name", ["", " alice", "al\nice", "a" * 300])
def test_unusable_usernames(name: str) -> None:
    assert _auth(directory_handler, name, "pw")[0] is None


def test_service_account_failure_is_an_error() -> None:
    with pytest.raises(LdapResultError):
        _auth(directory_handler, "alice", "Wonder-Land-1", bind_password="wrong")


def test_direct_bind_template_escapes_the_dn() -> None:
    entry, srv = _auth(
        directory_handler,
        "alice",
        "Wonder-Land-1",
        user_dn_template="uid={username},ou=people,dc=example,dc=com",
    )
    assert entry is not None
    entry, srv = _auth(
        directory_handler,
        "alice,ou=people",
        "Wonder-Land-1",
        user_dn_template="uid={username},ou=people,dc=example,dc=com",
    )
    assert entry is None
    assert (
        srv.requests[0].children[1].value == b"uid=alice\\,ou\\=people,ou=people,dc=example,dc=com"
    )


def test_injection_in_username_is_a_literal_search() -> None:
    entry, srv = _auth(directory_handler, "*)(uid=*", "Wonder-Land-1")
    assert entry is None
    filt = srv.requests[1].children[6]
    assert filt.children[1].children[1].value == b"*)(uid=*"


def _conn(handler: Handler, **kw: Any) -> LdapConnection:
    srv = FakeServer(handler)
    return LdapConnection(
        "h", 389, security="plain", addresses=["192.0.2.1"], connector=srv.connector, **kw
    )


def test_oversized_message_is_refused() -> None:
    def big(mid: int, op: Element) -> list[bytes]:
        return [ber_seq(ber_int(mid), ber_str("x" * 5000, 0x61))]

    with pytest.raises(LdapError, match="too large"), _conn(big, max_message_bytes=1000) as c:
        c.bind("cn=a", "b")


def test_claimed_huge_length_is_refused_before_reading() -> None:
    def huge(mid: int, op: Element) -> list[bytes]:
        return [b"\x30\x84\x7f\xff\xff\xff"]

    with pytest.raises(LdapError, match="too large"), _conn(huge) as c:
        c.bind("cn=a", "b")


def test_response_timeout() -> None:
    def slow(mid: int, op: Element) -> list[bytes]:
        return [b"SLEEP", _result(mid, 0x61, 0)]

    with pytest.raises(LdapError, match="timed out"), _conn(slow, timeout=0.3) as c:
        c.bind("cn=a", "b")


def test_slowloris_trickle_hits_the_total_deadline() -> None:
    def trickle(mid: int, op: Element) -> list[bytes]:
        return [b"\x30", b"SLEEP", b"\x05"]

    started = time.monotonic()
    with pytest.raises(LdapError, match="timed out"), _conn(trickle, timeout=0.5) as c:
        c.bind("cn=a", "b")
    assert time.monotonic() - started < 1.4


@pytest.mark.parametrize(
    "reply",
    [
        lambda mid: _result(mid + 1, 0x61, 0),  # wrong message id
        lambda mid: _result(0, 0x78, 52, "shutting down"),  # notice of disconnection
        lambda mid: ber_seq(ber_int(mid), tlv(0x61, ber_int(0, 0x0A))),  # short result
        lambda mid: ber_seq(ber_int(mid), ber_str("x", 0x04)),  # primitive op
        lambda mid: b"\x04\x01x",  # not a SEQUENCE
        lambda mid: ber_seq(ber_int(mid), tlv(0x61, b""), ber_int(1)),  # bad controls
        lambda mid: _result(mid, 0x65, 0),  # search done in answer to a bind
    ],
)
def test_protocol_violations(reply: Callable[[int], bytes]) -> None:
    with pytest.raises(LdapError), _conn(lambda mid, op: [reply(mid)]) as c:
        c.bind("cn=a", "b")


def test_search_entry_limit_and_references() -> None:
    def flood(mid: int, op: Element) -> list[bytes]:
        ref = ber_seq(ber_int(mid), tlv(0x73, ber_str("ldap://elsewhere/")))
        entries = [_entry_msg(mid, f"cn={i}", {}) for i in range(ldap.MAX_ENTRIES + 1)]
        return [ref, *entries, _result(mid, 0x65, 0)]

    with pytest.raises(LdapError, match="too many"), _conn(flood) as c:
        c.search("dc=x", "(cn=*)")


def test_starttls_refuses_plaintext_injected_after_the_response() -> None:
    def inject(mid: int, op: Element) -> list[bytes]:
        return [_result(mid, 0x78, 0) + _result(mid + 1, 0x61, 0)]

    srv = FakeServer(inject)
    with pytest.raises(LdapError, match="before the TLS handshake"):
        LdapConnection(
            "h", 389, security="starttls", addresses=["192.0.2.1"], connector=srv.connector
        )


def test_starttls_refused_by_server() -> None:
    srv = FakeServer(lambda mid, op: [_result(mid, 0x78, 2, "no")])
    with pytest.raises(LdapResultError):
        LdapConnection(
            "h", 389, security="starttls", addresses=["192.0.2.1"], connector=srv.connector
        )


def test_ssrf_guard_applies_to_ldap_hosts() -> None:
    with pytest.raises(LdapError, match="not allowed"):
        ldap.resolve_checked("127.0.0.1", 636, SsrfPolicy())
    assert ldap.resolve_checked("127.0.0.1", 636, SsrfPolicy(allow_private=True)) == ["127.0.0.1"]


def test_ssrf_guard_applies_allowed_ports() -> None:
    policy = SsrfPolicy(allow_private=True, allowed_ports=frozenset({636}))
    assert ldap.resolve_checked("127.0.0.1", 636, policy) == ["127.0.0.1"]
    with pytest.raises(LdapError, match="port"):
        ldap.resolve_checked("127.0.0.1", 389, policy)


def test_bind_with_an_empty_name_is_refused() -> None:
    """A server could answer with an empty DN: binding to it would be anonymous, not a check."""
    with pytest.raises(LdapError, match="empty"), _conn(directory_handler) as c:
        c.bind("", "password")


def test_search_deadline_covers_the_whole_search() -> None:
    def drip(mid: int, op: Element) -> list[bytes]:
        out: list[bytes] = []
        for i in range(ldap.MAX_ENTRIES):
            out += [_entry_msg(mid, f"cn={i}", {}), b"SLEEP"]
        return out

    started = time.monotonic()
    with pytest.raises(LdapError, match="timed out"), _conn(drip, timeout=2.0) as c:
        c.search("dc=x", "(cn=*)")
    assert time.monotonic() - started < 4.0


def test_check_directory_binds_the_service_account() -> None:
    srv = FakeServer(directory_handler)
    ldap.check_directory(DIRECTORY, connector=srv.connector, addresses=["192.0.2.1"])
    assert [r.tag for r in srv.requests[:1]] == [0x60]
    wrong = LdapDirectory(**{**DIRECTORY.__dict__, "bind_password": "wrong"})
    srv2 = FakeServer(directory_handler)
    with pytest.raises(LdapResultError):
        ldap.check_directory(wrong, connector=srv2.connector, addresses=["192.0.2.1"])


def test_invalid_security_mode() -> None:
    with pytest.raises(LdapError):
        LdapConnection("h", 1, security="none", addresses=["1"])


# --------------------------------------------------------------------------- real TLS


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[int, str]]:
    """An LDAPS listener on 127.0.0.1 with a certificate for ``ldap.test``; yields (port, CA)."""
    ca_key = x.generate_key()
    ca = x.build_certificate(subject_key=ca_key, common_name="Test CA", is_ca=True)
    key = x.generate_key()
    cert = x.build_certificate(
        subject_key=key,
        common_name="ldap.test",
        issuer=ca,
        issuer_key=ca_key,
        dns_names=["ldap.test"],
    )
    (tmp_path / "c.pem").write_text(x.der_to_pem(cert.der) + x.der_to_pem(ca.der))
    (tmp_path / "k.pem").write_text(x.private_key_pem(key))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except OSError:
                return
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
                data = conn.recv(4096)
                msg = decode(data)
                mid = int.from_bytes(msg.children[0].value, "big")
                conn.sendall(_result(mid, 0x61, 0))
                conn.recv(4096)
                conn.close()
            except (OSError, LdapError):
                raw.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield listener.getsockname()[1], x.der_to_pem(ca.der)
    stop.set()
    listener.close()


def test_ldaps_verifies_the_server_certificate(tls_server: tuple[int, str]) -> None:
    port, ca = tls_server
    kw: dict[str, Any] = {"security": "ldaps", "addresses": ["127.0.0.1"], "timeout": 3}
    with LdapConnection("ldap.test", port, ca_pem=ca, **kw) as c:
        c.bind("cn=a", "b")
    with pytest.raises(LdapError, match="TLS"):
        LdapConnection("ldap.test", port, **kw)  # system store does not trust the test CA
    with pytest.raises(LdapError, match="TLS"):
        LdapConnection("other.test", port, ca_pem=ca, **kw)  # host name mismatch
    with pytest.raises(LdapError, match="TLS"):
        LdapConnection("ldap.test", port, ca_pem="not a certificate", **kw)
