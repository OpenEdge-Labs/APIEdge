# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""A minimal LDAPv3 client: simple bind and search (T-023, VP-010, ADR 0016).

Written on the standard library only (``socket``, ``ssl``), because the maintained pure-Python
LDAP client is LGPL-licensed and the permissive ones need C libraries. It implements exactly what
APIEdge needs to check a user's password against LDAP or Active Directory:

* **Transport security** - ``ldaps`` (TLS from the first byte) or ``starttls`` (RFC 4511 4.14),
  always with certificate and host-name verification; ``plain`` LDAP only when the directory is
  explicitly configured for it (on-prem labs). The TCP connection goes to an address that passed
  the SSRF guard, never to a re-resolved name.
* **Strict BER** - definite lengths only, single-byte tags, bounded lengths, nesting depth and
  element counts; a message larger than ``max_message_bytes`` or a response that takes longer
  than the timeout ends the connection. Unknown or malformed input raises :class:`LdapError`.
* **Injection safety** - user input never becomes filter syntax: :func:`escape_filter_value`
  (RFC 4515) is applied before a value is placed in a filter template, and the template itself is
  parsed into the BER filter structure by :func:`parse_filter`, which accepts only well-formed
  filters. DN values are escaped with :func:`escape_dn_value` (RFC 4514).
* **No unauthenticated binds** - an empty password is refused before it reaches the server
  (RFC 4513 5.1.2: a simple bind with a name and no password is an *unauthenticated* bind that
  many servers report as successful).

Only these operations exist: bind (simple), search, StartTLS and unbind. Referrals are not
followed and search references are ignored.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from apiedge.security.ssrf import SsrfError, SsrfPolicy, check_ip

# --------------------------------------------------------------------------- limits

MAX_MESSAGE_BYTES = 1024 * 1024  # one LDAP message (a search entry) at most
MAX_DEPTH = 12  # nesting of constructed elements
MAX_ELEMENTS = 20_000  # elements in one message
MAX_FILTER_LENGTH = 4096
MAX_FILTER_DEPTH = 10
MAX_ENTRIES = 50  # search results read before giving up
MAX_INPUT = 1024  # username / password / DN length accepted from callers

# --------------------------------------------------------------------------- BER tags

UNIVERSAL_BOOLEAN = 0x01
UNIVERSAL_INTEGER = 0x02
UNIVERSAL_OCTET_STRING = 0x04
UNIVERSAL_NULL = 0x05
UNIVERSAL_ENUMERATED = 0x0A
SEQUENCE = 0x30
SET = 0x31

BIND_REQUEST = 0x60  # [APPLICATION 0] constructed
BIND_RESPONSE = 0x61
UNBIND_REQUEST = 0x42  # [APPLICATION 2] primitive
SEARCH_REQUEST = 0x63
SEARCH_RESULT_ENTRY = 0x64
SEARCH_RESULT_DONE = 0x65
SEARCH_RESULT_REFERENCE = 0x73
EXTENDED_REQUEST = 0x77
EXTENDED_RESPONSE = 0x78
CONTROLS = 0xA0

STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"

RESULT_SUCCESS = 0
RESULT_INVALID_CREDENTIALS = 49

SCOPE_BASE, SCOPE_ONE, SCOPE_SUB = 0, 1, 2


class LdapError(Exception):
    """Protocol, transport or decoding error. Messages never contain passwords."""


class LdapResultError(LdapError):
    """The server answered an operation with a non-success result code."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"LDAP result {code}: {message[:200]}")
        self.code = code


# --------------------------------------------------------------------------- BER encoding


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def ber_int(value: int, tag: int = UNIVERSAL_INTEGER) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return tlv(tag, value.to_bytes(size, "big", signed=True))


def ber_str(value: bytes | str, tag: int = UNIVERSAL_OCTET_STRING) -> bytes:
    return tlv(tag, value.encode("utf-8") if isinstance(value, str) else value)


def ber_bool(value: bool) -> bytes:
    return tlv(UNIVERSAL_BOOLEAN, b"\xff" if value else b"\x00")


def ber_seq(*parts: bytes, tag: int = SEQUENCE) -> bytes:
    return tlv(tag, b"".join(parts))


# --------------------------------------------------------------------------- BER decoding


@dataclass(frozen=True)
class Element:
    tag: int
    value: bytes  # content octets (primitive) - children are decoded on demand
    children: tuple[Element, ...] = ()

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


@dataclass
class _Budget:
    elements: int = 0


def _read_header(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """(tag, content length, content start) of the element at ``pos``."""
    if pos + 2 > end:
        raise LdapError("truncated BER element")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise LdapError("BER high tag numbers are not used by LDAP")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise LdapError("indefinite BER lengths are not allowed in LDAP")
    else:
        count = first & 0x7F
        if count > 4:
            raise LdapError("BER length field too long")
        if pos + count > end:
            raise LdapError("truncated BER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if length > end - pos:
        raise LdapError("BER length exceeds the enclosing element")
    return tag, length, pos


def _decode(data: bytes, pos: int, end: int, depth: int, budget: _Budget) -> tuple[Element, int]:
    budget.elements += 1
    if budget.elements > MAX_ELEMENTS:
        raise LdapError("too many BER elements")
    tag, length, start = _read_header(data, pos, end)
    stop = start + length
    if not tag & 0x20:
        return Element(tag, data[start:stop]), stop
    if depth >= MAX_DEPTH:
        raise LdapError("BER nesting too deep")
    children: list[Element] = []
    cur = start
    while cur < stop:
        child, cur = _decode(data, cur, stop, depth + 1, budget)
        children.append(child)
    return Element(tag, b"", tuple(children)), stop


def decode(data: bytes) -> Element:
    """Decode exactly one complete BER element (trailing bytes are an error)."""
    element, end = _decode(data, 0, len(data), 0, _Budget())
    if end != len(data):
        raise LdapError("trailing bytes after BER element")
    return element


def _as_int(e: Element, tag: int = UNIVERSAL_INTEGER) -> int:
    if e.tag != tag or not 1 <= len(e.value) <= 4:
        raise LdapError("expected a small BER integer")
    return int.from_bytes(e.value, "big", signed=True)


def _as_bytes(e: Element, tag: int = UNIVERSAL_OCTET_STRING) -> bytes:
    if e.tag != tag:
        raise LdapError("expected a BER octet string")
    return e.value


def _as_text(e: Element) -> str:
    try:
        return _as_bytes(e).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LdapError("LDAP string is not valid UTF-8") from exc


# --------------------------------------------------------------------------- escaping


def escape_filter_value(value: str) -> str:
    """Escape a value for use inside an LDAP filter (RFC 4515 section 3).

    ``*``, ``(``, ``)``, ``\\`` and NUL become ``\\2a``, ``\\28``, ``\\29``, ``\\5c`` and
    ``\\00``, so user input can only ever be an assertion value, never filter syntax.
    """
    out = []
    for ch in value:
        if ch in "*()\\\x00":
            out.append(f"\\{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def escape_dn_value(value: str) -> str:
    """Escape an attribute value for use inside a DN (RFC 4514 section 2.4)."""
    out = []
    for i, ch in enumerate(value):
        if ch in ',+"\\<>;=' or (ch == "#" and i == 0) or (ch == " " and i in (0, len(value) - 1)):
            out.append("\\" + ch)
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def fill_template(template: str, **values: str) -> str:
    """Replace ``{name}`` placeholders by already-escaped values (no format-string features)."""
    out = template
    for name, value in values.items():
        out = out.replace("{" + name + "}", value)
    return out


# --------------------------------------------------------------------------- filters (RFC 4515)

_ATTR_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.;")


def _unescape(text: str) -> bytes:
    """An assertion value with ``\\XX`` escapes decoded; raw ``*()`` or NUL are rejected."""
    out = bytearray()
    raw = text.encode("utf-8")
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x5C:
            pair = raw[i + 1 : i + 3]
            if len(pair) != 2 or not all(c in b"0123456789abcdefABCDEF" for c in pair):
                raise LdapError("invalid escape in LDAP filter value")
            out.append(int(pair, 16))
            i += 3
            continue
        if b in b"*()\x00":
            raise LdapError("unescaped special character in LDAP filter value")
        out.append(b)
        i += 1
    return bytes(out)


def _attr(text: str) -> str:
    if not text or len(text) > 128 or not set(text) <= _ATTR_CHARS:
        raise LdapError("invalid attribute description in LDAP filter")
    return text


class _FilterParser:
    def __init__(self, text: str) -> None:
        if len(text) > MAX_FILTER_LENGTH:
            raise LdapError("LDAP filter too long")
        self.text = text
        self.pos = 0

    def parse(self) -> bytes:
        result = self._filter(0)
        if self.pos != len(self.text):
            raise LdapError("trailing characters after LDAP filter")
        return result

    def _expect(self, ch: str) -> None:
        if self.pos >= len(self.text) or self.text[self.pos] != ch:
            raise LdapError(f"malformed LDAP filter: expected '{ch}' at {self.pos}")
        self.pos += 1

    def _filter(self, depth: int) -> bytes:
        if depth > MAX_FILTER_DEPTH:
            raise LdapError("LDAP filter nested too deeply")
        self._expect("(")
        if self.pos >= len(self.text):
            raise LdapError("malformed LDAP filter")
        op = self.text[self.pos]
        if op in "&|":
            self.pos += 1
            parts = []
            while self.pos < len(self.text) and self.text[self.pos] == "(":
                parts.append(self._filter(depth + 1))
            if not parts:
                raise LdapError("empty LDAP filter set")
            encoded = tlv(0xA0 if op == "&" else 0xA1, b"".join(parts))
        elif op == "!":
            self.pos += 1
            encoded = tlv(0xA2, self._filter(depth + 1))
        else:
            encoded = self._item()
        self._expect(")")
        return encoded

    def _item(self) -> bytes:
        end = self.text.find(")", self.pos)
        if end < 0:
            raise LdapError("malformed LDAP filter: missing ')'")
        item = self.text[self.pos : end]
        self.pos = end
        if "(" in item:
            raise LdapError("malformed LDAP filter item")
        eq = item.find("=")
        if eq <= 0:
            raise LdapError("malformed LDAP filter item: no attribute or operator")
        tags = {">": 0xA5, "<": 0xA6, "~": 0xA8}
        if item[eq - 1] in tags:  # attribute names cannot contain these, so this is the operator
            left, right = item[: eq - 1], item[eq + 1 :]
            return ber_seq(ber_str(_attr(left)), ber_str(_unescape(right)), tag=tags[item[eq - 1]])
        left, right = item[:eq], item[eq + 1 :]
        if ":" in left:
            return self._extensible(left, right)
        attr = _attr(left)
        if right == "*":
            return tlv(0x87, attr.encode("ascii"))  # present
        if "*" in right:
            return self._substrings(attr, right)
        return ber_seq(ber_str(attr), ber_str(_unescape(right)), tag=0xA3)  # equalityMatch

    @staticmethod
    def _substrings(attr: str, right: str) -> bytes:
        pieces = right.split("*")
        parts = []
        if pieces[0]:
            parts.append(ber_str(_unescape(pieces[0]), 0x80))  # initial
        for middle in pieces[1:-1]:
            if not middle:
                raise LdapError("empty substring in LDAP filter")
            parts.append(ber_str(_unescape(middle), 0x81))  # any
        if pieces[-1]:
            parts.append(ber_str(_unescape(pieces[-1]), 0x82))  # final
        return ber_seq(ber_str(attr), ber_seq(*parts), tag=0xA4)

    @staticmethod
    def _extensible(left: str, right: str) -> bytes:
        # attr[:dn][:rule]:=value  or  [:dn]:rule:=value
        if not left.endswith(":"):
            raise LdapError("malformed extensible match in LDAP filter")
        fields = left[:-1].split(":")
        attr, rest = fields[0], fields[1:]
        dn = False
        if rest and rest[0].lower() == "dn":
            dn, rest = True, rest[1:]
        if len(rest) > 1:
            raise LdapError("malformed extensible match in LDAP filter")
        rule = rest[0] if rest else ""
        if not attr and not rule:
            raise LdapError("extensible match needs an attribute or a matching rule")
        parts = []
        if rule:
            parts.append(ber_str(_attr(rule), 0x81))
        if attr:
            parts.append(ber_str(_attr(attr), 0x82))
        parts.append(ber_str(_unescape(right), 0x83))
        if dn:
            parts.append(tlv(0x84, b"\xff"))
        return ber_seq(*parts, tag=0xA9)


def parse_filter(text: str) -> bytes:
    """The BER encoding of an RFC 4515 filter string (raises :class:`LdapError` if invalid)."""
    return _FilterParser(text.strip()).parse()


# --------------------------------------------------------------------------- client


@dataclass(frozen=True)
class LdapEntry:
    dn: str
    attributes: dict[str, list[str]] = field(default_factory=dict)

    def first(self, name: str) -> str | None:
        for key, values in self.attributes.items():
            if key.lower() == name.lower() and values:
                return values[0]
        return None


Connector = Callable[[str, int, float], socket.socket]


def _default_connector(address: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


def resolve_checked(host: str, port: int, policy: SsrfPolicy) -> list[str]:
    """Every address ``host`` resolves to, all checked by the SSRF guard (raises if any fails)."""
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise LdapError(f"LDAP port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise LdapError(f"cannot resolve LDAP host {host!r}") from exc
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise LdapError(f"cannot resolve LDAP host {host!r}")
    for address in addresses:
        try:
            check_ip(address, policy)
        except (SsrfError, ValueError) as exc:
            raise LdapError(f"LDAP host {host!r} is not allowed: {exc}") from exc
    return addresses


class LdapConnection:
    """One LDAP connection (not thread-safe; use one per authentication)."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        security: str = "ldaps",
        ca_pem: str | None = None,
        timeout: float = 5.0,
        ssrf_policy: SsrfPolicy | None = None,
        addresses: Sequence[str] | None = None,
        connector: Connector = _default_connector,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        if security not in ("ldaps", "starttls", "plain"):
            raise LdapError("security must be ldaps, starttls or plain")
        self.host = host
        self.port = port
        self.security = security
        self.timeout = timeout
        self.max_message_bytes = max_message_bytes
        self._ca_pem = ca_pem
        self._next_id = 1
        self._buffer = b""
        if addresses is None:
            addresses = resolve_checked(host, port, ssrf_policy or SsrfPolicy())
        sock: socket.socket | None = None
        last: Exception | None = None
        for address in addresses:
            try:
                sock = connector(address, port, timeout)
                break
            except OSError as exc:
                last = exc
        if sock is None:
            raise LdapError(f"cannot connect to LDAP server {host}:{port}") from last
        sock.settimeout(timeout)
        self._sock: socket.socket | ssl.SSLSocket = sock
        try:
            if security == "ldaps":
                self._wrap_tls()
            elif security == "starttls":
                self._start_tls()
        except BaseException:
            self.close()
            raise

    # ---- TLS

    def _tls_context(self) -> ssl.SSLContext:
        ctx = (
            ssl.create_default_context(cadata=self._ca_pem)
            if self._ca_pem
            else (ssl.create_default_context())
        )
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _wrap_tls(self) -> None:
        try:
            self._sock = self._tls_context().wrap_socket(self._sock, server_hostname=self.host)
        except (
            OSError,
            ValueError,
        ) as exc:  # ssl errors are OSErrors; ValueError: unusable CA data
            raise LdapError(f"TLS handshake with the LDAP server failed: {exc}") from exc

    def _start_tls(self) -> None:
        mid = self._send(ber_seq(ber_str(STARTTLS_OID, 0x80), tag=EXTENDED_REQUEST))
        op = self._receive(mid)
        if op.tag != EXTENDED_RESPONSE:
            raise LdapError("unexpected answer to StartTLS")
        _check_result(op)
        if self._buffer:
            raise LdapError("data received before the TLS handshake")  # no plaintext injection
        self._wrap_tls()

    # ---- framing

    def _send(self, op: bytes, controls: bytes = b"") -> int:
        mid = self._next_id
        self._next_id += 1
        try:
            self._sock.sendall(ber_seq(ber_int(mid), op, controls))
        except OSError as exc:
            raise LdapError("sending to the LDAP server failed") from exc
        return mid

    def _read_message(self, deadline: float) -> Element:
        """Read exactly one LDAPMessage (bounded size, bounded total time)."""
        while True:
            need = self._frame_size()
            if need is not None and len(self._buffer) >= need:
                frame, self._buffer = self._buffer[:need], self._buffer[need:]
                return decode(frame)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LdapError("LDAP server response timed out")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(65536)
            except TimeoutError as exc:
                raise LdapError("LDAP server response timed out") from exc
            except OSError as exc:
                raise LdapError("reading from the LDAP server failed") from exc
            if not chunk:
                raise LdapError("LDAP server closed the connection")
            self._buffer += chunk
            if len(self._buffer) > self.max_message_bytes + 16:
                raise LdapError("LDAP message too large")

    def _frame_size(self) -> int | None:
        buf = self._buffer
        if len(buf) < 2:
            return None
        if buf[0] != SEQUENCE:
            raise LdapError("LDAP message is not a SEQUENCE")
        first = buf[1]
        if first < 0x80:
            size = 2 + first
        elif first == 0x80:
            raise LdapError("indefinite BER lengths are not allowed in LDAP")
        else:
            count = first & 0x7F
            if count > 4:
                raise LdapError("BER length field too long")
            if len(buf) < 2 + count:
                return None
            size = 2 + count + int.from_bytes(buf[2 : 2 + count], "big")
        if size > self.max_message_bytes:
            raise LdapError("LDAP message too large")
        return size

    def _receive(self, mid: int, deadline: float | None = None) -> Element:
        """The protocolOp of the next message for ``mid`` (notices of disconnection raise)."""
        message = self._read_message(deadline or time.monotonic() + self.timeout)
        if message.tag != SEQUENCE or len(message.children) not in (2, 3):
            raise LdapError("malformed LDAP message")
        if len(message.children) == 3 and message.children[2].tag != CONTROLS:
            raise LdapError("malformed LDAP message controls")
        got = _as_int(message.children[0])
        op = message.children[1]
        if got == 0 and op.tag == EXTENDED_RESPONSE:
            raise LdapError("LDAP server sent a notice of disconnection")
        if got != mid:
            raise LdapError("LDAP response for an unexpected message id")
        if not op.constructed:
            raise LdapError("malformed LDAP protocol operation")
        return op

    # ---- operations

    def bind(self, dn: str, password: str) -> None:
        """Simple bind; raises :class:`LdapResultError` (code 49) for wrong credentials."""
        if not dn or not password:  # RFC 4513 5.1: an empty name or password is not authentication
            raise LdapError("empty names and passwords are refused (unauthenticated bind)")
        if len(dn) > MAX_INPUT or len(password) > MAX_INPUT:
            raise LdapError("bind name or password too long")
        op = ber_seq(ber_int(3), ber_str(dn), ber_str(password, 0x80), tag=BIND_REQUEST)
        mid = self._send(op)
        response = self._receive(mid)
        if response.tag != BIND_RESPONSE:
            raise LdapError("unexpected answer to bind")
        _check_result(response)

    def search(
        self,
        base: str,
        filter_text: str,
        attributes: Sequence[str] = (),
        *,
        scope: int = SCOPE_SUB,
        size_limit: int = 2,
    ) -> list[LdapEntry]:
        """Entries matching ``filter_text`` (an RFC 4515 filter; escape user values first)."""
        if scope not in (SCOPE_BASE, SCOPE_ONE, SCOPE_SUB):
            raise LdapError("invalid search scope")
        filt = parse_filter(filter_text)
        op = ber_seq(
            ber_str(base),
            ber_int(scope, UNIVERSAL_ENUMERATED),
            ber_int(0, UNIVERSAL_ENUMERATED),  # neverDerefAliases
            ber_int(max(0, min(size_limit, MAX_ENTRIES))),
            ber_int(max(1, int(self.timeout))),
            ber_bool(False),
            filt,
            ber_seq(*(ber_str(_attr(a)) for a in attributes)),
            tag=SEARCH_REQUEST,
        )
        mid = self._send(op)
        deadline = time.monotonic() + self.timeout  # for the whole search, not for each message
        entries: list[LdapEntry] = []
        for _ in range(MAX_ENTRIES * 4):
            response = self._receive(mid, deadline)
            if response.tag == SEARCH_RESULT_ENTRY:
                if len(entries) >= MAX_ENTRIES:
                    raise LdapError("too many LDAP search results")
                entries.append(_entry(response))
            elif response.tag == SEARCH_RESULT_REFERENCE:
                continue  # referrals are not followed
            elif response.tag == SEARCH_RESULT_DONE:
                _check_result(response, allow=(4,))  # 4 = sizeLimitExceeded: entries are enough
                return entries
            else:
                raise LdapError("unexpected answer to search")
        raise LdapError("too many LDAP search responses")

    def close(self) -> None:
        try:
            self._sock.settimeout(1.0)
            self._send(tlv(UNBIND_REQUEST, b""))
        except (LdapError, OSError):
            pass
        with contextlib.suppress(OSError):
            self._sock.close()

    def __enter__(self) -> LdapConnection:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _check_result(op: Element, allow: tuple[int, ...] = ()) -> None:
    if len(op.children) < 3:
        raise LdapError("malformed LDAP result")
    code = _as_int(op.children[0], UNIVERSAL_ENUMERATED)
    _as_bytes(op.children[1])  # matchedDN
    message = _as_bytes(op.children[2]).decode("utf-8", "replace")
    if code != RESULT_SUCCESS and code not in allow:
        raise LdapResultError(code, message)


def _entry(op: Element) -> LdapEntry:
    if len(op.children) != 2 or op.children[1].tag != SEQUENCE:
        raise LdapError("malformed LDAP search entry")
    dn = _as_text(op.children[0])
    attributes: dict[str, list[str]] = {}
    for attr in op.children[1].children:
        if attr.tag != SEQUENCE or len(attr.children) != 2 or attr.children[1].tag != SET:
            raise LdapError("malformed LDAP attribute")
        name = _as_text(attr.children[0])
        values = []
        for v in attr.children[1].children:
            raw = _as_bytes(v)
            try:
                values.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                continue  # binary attributes (photos, GUIDs) are not used
        attributes[name] = values
    return LdapEntry(dn, attributes)


# --------------------------------------------------------------------------- authentication


@dataclass(frozen=True)
class LdapDirectory:
    """How to find and check a user in one directory (a tenant's LDAP directory row)."""

    host: str
    port: int = 636
    security: str = "ldaps"  # ldaps | starttls | plain
    ca_pem: str | None = None  # trusted CAs (a tenant truststore); None = the system store
    timeout: float = 5.0
    bind_dn: str = ""  # service account for the user search; empty = anonymous search
    bind_password: str = ""
    user_base_dn: str = ""
    user_filter: str = "(uid={username})"
    # Bind directly as this DN instead of searching ({username} is DN-escaped), for example
    # "uid={username},ou=people,dc=example,dc=com" or Active Directory's "{username}@corp.example".
    user_dn_template: str = ""
    username_attribute: str = "uid"
    email_attribute: str = "mail"
    name_attribute: str = "cn"


def bind_password_aad(tenant_id: int, directory_id: int) -> str:
    """Associated data binding a stored service-account password to its directory."""
    return f"ldap:{tenant_id}:{directory_id}:bind_password"


def check_directory(
    directory: LdapDirectory,
    *,
    ssrf_policy: SsrfPolicy | None = None,
    connector: Connector = _default_connector,
    addresses: Sequence[str] | None = None,
) -> None:
    """Connect and bind as the service account (if any); raises :class:`LdapError` on failure."""
    with LdapConnection(
        directory.host,
        directory.port,
        security=directory.security,
        ca_pem=directory.ca_pem,
        timeout=directory.timeout,
        ssrf_policy=ssrf_policy,
        connector=connector,
        addresses=addresses,
    ) as conn:
        if directory.bind_dn:
            conn.bind(directory.bind_dn, directory.bind_password)


def _usable_username(username: str) -> bool:
    return (
        0 < len(username) <= 256
        and username.strip() == username
        and all(ch.isprintable() for ch in username)
    )


def authenticate(
    directory: LdapDirectory,
    username: str,
    password: str,
    *,
    ssrf_policy: SsrfPolicy | None = None,
    connector: Connector = _default_connector,
    addresses: Sequence[str] | None = None,
) -> LdapEntry | None:
    """The user's entry if ``username``/``password`` are valid in ``directory``, else None.

    Raises :class:`LdapError` when the directory cannot be used (unreachable, TLS failure,
    service-account bind failure, malformed answers), so callers can tell "wrong password" from
    "directory down" and fail closed.
    """
    if not _usable_username(username) or not password or len(password) > MAX_INPUT:
        return None
    attrs = [
        a
        for a in (directory.username_attribute, directory.email_attribute, directory.name_attribute)
        if a
    ]
    with LdapConnection(
        directory.host,
        directory.port,
        security=directory.security,
        ca_pem=directory.ca_pem,
        timeout=directory.timeout,
        ssrf_policy=ssrf_policy,
        connector=connector,
        addresses=addresses,
    ) as conn:
        if directory.user_dn_template:
            dn = fill_template(directory.user_dn_template, username=escape_dn_value(username))
            try:
                conn.bind(dn, password)
            except LdapResultError as exc:
                if exc.code == RESULT_INVALID_CREDENTIALS:
                    return None
                raise
            entries = []
            if "=" in dn:  # a real DN (not a UPN): read the user's attributes
                try:
                    entries = conn.search(dn, "(objectClass=*)", attrs, scope=SCOPE_BASE)
                except LdapResultError:
                    entries = []
            return (
                entries[0]
                if entries
                else LdapEntry(dn, {directory.username_attribute or "uid": [username]})
            )
        if directory.bind_dn:
            conn.bind(directory.bind_dn, directory.bind_password)  # failure: LdapResultError
        user_filter = fill_template(directory.user_filter, username=escape_filter_value(username))
        entries = conn.search(directory.user_base_dn, user_filter, attrs, size_limit=2)
        if len(entries) != 1:
            return None  # unknown or ambiguous user
        try:
            conn.bind(entries[0].dn, password)
        except LdapResultError as exc:
            if exc.code == RESULT_INVALID_CREDENTIALS:
                return None
            raise
        return entries[0]
