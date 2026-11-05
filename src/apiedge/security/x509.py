# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""X.509 certificates without a native crypto dependency (T-023, ADR 0013).

A small, strict DER reader for the certificate fields APIEdge needs (subject, issuer, serial,
validity, public key, basic constraints, key usage, extended key usage, subject alternative
names), signature verification and path building against a set of trust anchors, and a
certificate builder used by ``apiedge tls self-signed`` and the tests. Signatures use
pycryptodome (RSA PKCS#1 v1.5, ECDSA, Ed25519); SHA-1 and MD5 signatures are refused.

Parsing is bounded: certificates larger than :data:`MAX_CERT_BYTES`, bundles with more than
:data:`MAX_BUNDLE_CERTS` certificates and nesting deeper than the X.509 structure are refused.
Revocation (CRL, OCSP) is not checked.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from Crypto.Hash import SHA256, SHA384, SHA512  # nosec B413 - pycryptodome (maintained)
from Crypto.PublicKey import ECC, RSA  # nosec B413
from Crypto.Signature import DSS, eddsa, pkcs1_15  # nosec B413

MAX_CERT_BYTES = 16 * 1024
MAX_BUNDLE_CERTS = 100
MAX_PEM_BYTES = 512 * 1024
MAX_CHAIN_DEPTH = 8


class CertificateError(ValueError):
    """A certificate, key or bundle that cannot be used."""


# --------------------------------------------------------------------------- DER reading


@dataclass(frozen=True)
class _Node:
    tag: int
    start: int  # first byte of the tag
    body: int  # first content byte
    end: int  # one past the last content byte


def _read(data: bytes, pos: int, limit: int | None = None) -> _Node:
    limit = len(data) if limit is None else limit
    if pos + 2 > limit:
        raise CertificateError("truncated DER")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise CertificateError("unsupported DER tag")
    length = data[pos + 1]
    body = pos + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or body + n > limit:
            raise CertificateError("invalid DER length")
        length = int.from_bytes(data[body : body + n], "big")
        body += n
    end = body + length
    if end > limit:
        raise CertificateError("truncated DER")
    return _Node(tag, pos, body, end)


def _children(data: bytes, node: _Node) -> list[_Node]:
    out: list[_Node] = []
    pos = node.body
    while pos < node.end:
        child = _read(data, pos, node.end)
        out.append(child)
        pos = child.end
        if len(out) > 1000:
            raise CertificateError("too many DER elements")
    return out


def _expect(node: _Node, tag: int, what: str) -> _Node:
    if node.tag != tag:
        raise CertificateError(f"invalid certificate ({what})")
    return node


def _oid(data: bytes, node: _Node) -> str:
    raw = data[node.body : node.end]
    if not raw:
        raise CertificateError("empty OID")
    parts = [str(min(raw[0] // 40, 2)), str(raw[0] - 40 * min(raw[0] // 40, 2))]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _int(data: bytes, node: _Node) -> int:
    return int.from_bytes(data[node.body : node.end], "big", signed=True)


_STRING_TAGS = {0x0C: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1", 0x1C: "utf-32-be"}


def _string(data: bytes, node: _Node) -> str:
    raw = data[node.body : node.end]
    if node.tag == 0x1E:
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode(_STRING_TAGS.get(node.tag, "latin-1"), errors="replace")


def _time(data: bytes, node: _Node) -> datetime:
    text = data[node.body : node.end].decode("ascii", errors="replace")
    try:
        if node.tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
            moment = datetime.strptime(text, "%y%m%d%H%M%SZ")
            if moment.year >= 2050:
                moment = moment.replace(year=moment.year - 100)
        elif node.tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
            moment = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            raise CertificateError("invalid certificate time")
    except ValueError as exc:
        raise CertificateError("invalid certificate time") from exc
    return moment.replace(tzinfo=UTC)


_NAME_KEYS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}
_ESCAPE = re.compile(r'([,+"\\<>;=])')
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _name(data: bytes, node: _Node) -> tuple[str, str]:
    """(RFC 4514 string, common name) of a Name."""
    rdns: list[str] = []
    cn = ""
    for rdn in _children(data, _expect(node, 0x30, "name")):
        parts: list[str] = []
        for atv in _children(data, _expect(rdn, 0x31, "name")):
            items = _children(data, _expect(atv, 0x30, "name"))
            if len(items) != 2:
                raise CertificateError("invalid certificate (name)")
            oid = _oid(data, _expect(items[0], 0x06, "name"))
            value = _CONTROL.sub("?", _string(data, items[1]))
            key = _NAME_KEYS.get(oid, oid)
            if key == "CN" and not cn:
                cn = value
            escaped = _ESCAPE.sub(r"\\\1", value)
            parts.append(f"{key}={escaped}")
        rdns.append("+".join(parts))
    return ",".join(reversed(rdns)), cn


# --------------------------------------------------------------------------- certificates

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
_SIG_ALGS: dict[str, tuple[str, Any]] = {
    "1.2.840.113549.1.1.11": ("rsa", SHA256),
    "1.2.840.113549.1.1.12": ("rsa", SHA384),
    "1.2.840.113549.1.1.13": ("rsa", SHA512),
    "1.2.840.10045.4.3.2": ("ecdsa", SHA256),
    "1.2.840.10045.4.3.3": ("ecdsa", SHA384),
    "1.2.840.10045.4.3.4": ("ecdsa", SHA512),
    OID_ED25519: ("ed25519", None),
}
EKU_SERVER = "1.3.6.1.5.5.7.3.1"
EKU_CLIENT = "1.3.6.1.5.5.7.3.2"
_KU_KEY_CERT_SIGN = 5  # bit number in KeyUsage


@dataclass(frozen=True)
class Certificate:
    """The parsed fields of one X.509 certificate."""

    der: bytes
    tbs: bytes
    signature_oid: str
    signature: bytes
    version: int
    serial: int
    issuer: str
    issuer_der: bytes
    subject: str
    subject_der: bytes
    common_name: str
    not_before: datetime
    not_after: datetime
    spki: bytes
    key_oid: str
    is_ca: bool | None  # None: no basic constraints extension
    key_cert_sign: bool | None  # None: no key usage extension
    extended_key_usage: frozenset[str] | None
    dns_names: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()
    fingerprint_sha256: str = field(default="")

    @property
    def key_type(self) -> str:
        if self.key_oid == OID_RSA:
            try:
                return f"RSA {RSA.import_key(self.spki).size_in_bits()}"
            except (ValueError, IndexError, TypeError):
                return "RSA"
        if self.key_oid == OID_EC:
            try:
                return f"EC {ECC.import_key(self.spki).curve}"
            except (ValueError, IndexError, TypeError):
                return "EC"
        if self.key_oid == OID_ED25519:
            return "Ed25519"
        return self.key_oid

    @property
    def is_self_issued(self) -> bool:
        return self.issuer_der == self.subject_der

    def pem(self) -> str:
        return der_to_pem(self.der)

    def valid_at(self, moment: datetime) -> bool:
        return self.not_before <= moment <= self.not_after


def parse_certificate(der: bytes) -> Certificate:
    """Parse one DER certificate (raises :class:`CertificateError`)."""
    if not der or len(der) > MAX_CERT_BYTES:
        raise CertificateError("certificate missing or too large")
    root = _expect(_read(der, 0), 0x30, "structure")
    if root.end != len(der):
        raise CertificateError("trailing data after the certificate")
    top = _children(der, root)
    if len(top) != 3:
        raise CertificateError("invalid certificate (structure)")
    tbs_node, alg_node, sig_node = top
    _expect(tbs_node, 0x30, "tbs")
    sig_alg = _oid(der, _expect(_children(der, _expect(alg_node, 0x30, "algorithm"))[0], 0x06, "a"))
    _expect(sig_node, 0x03, "signature")
    signature = der[sig_node.body + 1 : sig_node.end]  # skip the unused-bits byte
    fields = _children(der, tbs_node)
    i = 0
    version = 1
    if fields and fields[0].tag == 0xA0:
        version = _int(der, _read(der, fields[0].body, fields[0].end)) + 1
        i = 1
    if len(fields) < i + 6:
        raise CertificateError("invalid certificate (tbs)")
    serial = _int(der, _expect(fields[i], 0x02, "serial"))
    issuer_node, validity, subject_node, spki_node = (
        fields[i + 2],
        fields[i + 3],
        fields[i + 4],
        fields[i + 5],
    )
    issuer, _ = _name(der, issuer_node)
    subject, cn = _name(der, subject_node)
    times = _children(der, _expect(validity, 0x30, "validity"))
    if len(times) != 2:
        raise CertificateError("invalid certificate (validity)")
    spki_parts = _children(der, _expect(spki_node, 0x30, "public key"))
    key_oid = _oid(der, _children(der, _expect(spki_parts[0], 0x30, "key"))[0])
    is_ca: bool | None = None
    key_cert_sign: bool | None = None
    eku: frozenset[str] | None = None
    dns: list[str] = []
    ips: list[str] = []
    for ext_wrap in fields[i + 6 :]:
        if ext_wrap.tag != 0xA3:
            continue
        seq = _read(der, ext_wrap.body, ext_wrap.end)
        for ext in _children(der, _expect(seq, 0x30, "extensions")):
            parts = _children(der, _expect(ext, 0x30, "extension"))
            oid = _oid(der, _expect(parts[0], 0x06, "extension"))
            value = _expect(parts[-1], 0x04, "extension")
            inner = _read(der, value.body, value.end)
            if oid == "2.5.29.19":  # basicConstraints
                items = _children(der, inner)
                is_ca = bool(items and items[0].tag == 0x01 and der[items[0].body] != 0)
            elif oid == "2.5.29.15":  # keyUsage BIT STRING
                bits = der[inner.body + 1 : inner.end]
                key_cert_sign = bool(bits) and bool(bits[0] & (0x80 >> _KU_KEY_CERT_SIGN))
            elif oid == "2.5.29.37":  # extKeyUsage
                eku = frozenset(_oid(der, n) for n in _children(der, inner))
            elif oid == "2.5.29.17":  # subjectAltName
                for name in _children(der, inner):
                    raw = der[name.body : name.end]
                    if name.tag == 0x82:
                        dns.append(_CONTROL.sub("?", raw.decode("ascii", errors="replace")))
                    elif name.tag == 0x87 and len(raw) in (4, 16):
                        ips.append(str(ipaddress.ip_address(raw)))
    return Certificate(
        der=der,
        tbs=der[tbs_node.start : tbs_node.end],
        signature_oid=sig_alg,
        signature=signature,
        version=version,
        serial=serial,
        issuer=issuer,
        issuer_der=der[issuer_node.start : issuer_node.end],
        subject=subject,
        subject_der=der[subject_node.start : subject_node.end],
        common_name=cn,
        not_before=_time(der, times[0]),
        not_after=_time(der, times[1]),
        spki=der[spki_node.start : spki_node.end],
        key_oid=key_oid,
        is_ca=is_ca,
        key_cert_sign=key_cert_sign,
        extended_key_usage=eku,
        dns_names=tuple(dns[:100]),
        ip_addresses=tuple(ips[:100]),
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
    )


# One character class with no "-" between the markers keeps matching linear (no ReDoS).
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----")


def der_to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def load_pem_certificates(text: str, *, limit: int = MAX_BUNDLE_CERTS) -> list[Certificate]:
    """Every certificate of a PEM bundle, in order (raises if none or too many)."""
    if len(text) > MAX_PEM_BYTES:
        raise CertificateError("the PEM bundle is too large")
    blocks = PEM_CERT_RE.findall(text)
    if not blocks:
        raise CertificateError("no PEM certificate found (-----BEGIN CERTIFICATE-----)")
    if len(blocks) > limit:
        raise CertificateError(f"at most {limit} certificates are allowed")
    out = []
    for n, block in enumerate(blocks, start=1):
        try:
            der = base64.b64decode("".join(block.split()), validate=True)
        except ValueError as exc:
            raise CertificateError(f"certificate {n}: invalid base64") from exc
        try:
            out.append(parse_certificate(der))
        except CertificateError as exc:
            raise CertificateError(f"certificate {n}: {exc}") from exc
    return out


def bundle_pem(certs: Iterable[Certificate]) -> str:
    return "".join(c.pem() for c in certs)


# --------------------------------------------------------------------------- keys and signatures

PrivateKey = Any  # RSA.RsaKey | ECC.EccKey (pycryptodome is untyped here)


def public_key(cert: Certificate) -> Any:
    try:
        if cert.key_oid == OID_RSA:
            return RSA.import_key(cert.spki)
        if cert.key_oid in (OID_EC, OID_ED25519):
            return ECC.import_key(cert.spki)
    except (ValueError, IndexError, TypeError) as exc:
        raise CertificateError("unreadable public key") from exc
    raise CertificateError("unsupported public key algorithm")


def verify_signature(cert: Certificate, issuer: Certificate) -> bool:
    """True when ``issuer``'s key signed ``cert``."""
    alg = _SIG_ALGS.get(cert.signature_oid)
    if alg is None:
        return False
    kind, digest = alg
    try:
        key = public_key(issuer)
        if kind == "rsa" and issuer.key_oid == OID_RSA:
            pkcs1_15.new(key).verify(digest.new(cert.tbs), cert.signature)
        elif kind == "ecdsa" and issuer.key_oid == OID_EC:
            DSS.new(key, "fips-186-3", encoding="der").verify(digest.new(cert.tbs), cert.signature)
        elif kind == "ed25519" and issuer.key_oid == OID_ED25519:
            eddsa.new(key, "rfc8032").verify(cert.tbs, cert.signature)
        else:
            return False
    except (ValueError, TypeError, CertificateError):
        return False
    return True


def _can_issue(cert: Certificate, anchor: bool) -> bool:
    if cert.key_cert_sign is False:
        return False
    if cert.is_ca is None:
        return anchor and cert.version == 1  # legacy v1 roots only as configured anchors
    return cert.is_ca


def verify_chain(
    leaf: Certificate,
    anchors: Sequence[Certificate],
    *,
    intermediates: Sequence[Certificate] = (),
    purpose: Literal["client", "server"] | None = None,
    now: datetime | None = None,
) -> str | None:
    """Check that ``leaf`` chains to one of ``anchors``; returns an error text or None.

    A leaf that is itself one of the anchors is accepted (certificate pinning). Every
    certificate on the path must be within its validity period; issuers must be CAs.
    """
    moment = now or datetime.now(UTC)
    if not leaf.valid_at(moment):
        return "expired" if moment > leaf.not_after else "not yet valid"
    if purpose is not None and leaf.extended_key_usage is not None:
        wanted = EKU_CLIENT if purpose == "client" else EKU_SERVER
        if wanted not in leaf.extended_key_usage and "2.5.29.37.0" not in leaf.extended_key_usage:
            return f"not valid for {purpose} authentication"
    pinned = {a.fingerprint_sha256 for a in anchors}
    if leaf.fingerprint_sha256 in pinned:
        return None
    current = leaf
    for _ in range(MAX_CHAIN_DEPTH):
        candidates = [(a, True) for a in anchors if a.subject_der == current.issuer_der] + [
            (c, False) for c in intermediates if c.subject_der == current.issuer_der
        ]
        for issuer, is_anchor in candidates:
            if not _can_issue(issuer, is_anchor) or not verify_signature(current, issuer):
                continue
            if not issuer.valid_at(moment):
                return "issuer certificate expired"
            if is_anchor:
                return None
            current = issuer
            break
        else:
            return "not issued by a trusted certificate"
    return "certificate chain too long"


def load_private_key(pem: str, passphrase: str | None = None) -> PrivateKey:
    """An RSA or EC private key from PEM (PKCS#8, PKCS#1 or SEC1, optionally encrypted)."""
    if len(pem) > 64 * 1024:
        raise CertificateError("the private key is too large")
    for loader in (RSA.import_key, ECC.import_key):
        try:
            key = loader(pem, passphrase) if passphrase else loader(pem)
        except (ValueError, IndexError, TypeError):
            continue
        if not key.has_private():
            raise CertificateError("this is a public key; a private key is needed")
        return key
    raise CertificateError("unreadable private key (wrong format or passphrase)")


def private_key_pem(key: PrivateKey) -> str:
    """Unencrypted PKCS#8 PEM (for storage inside the secrets box only)."""
    if isinstance(key, RSA.RsaKey):
        return str(key.export_key(format="PEM", pkcs=8).decode("ascii"))
    return str(key.export_key(format="PEM"))


def key_matches(cert: Certificate, key: PrivateKey) -> bool:
    try:
        return bool(
            key.public_key().export_key(format="DER") == public_key(cert).export_key(format="DER")
        )
    except (ValueError, TypeError, CertificateError):
        return False


def describe_key(key: PrivateKey) -> str:
    if isinstance(key, RSA.RsaKey):
        return f"RSA {key.size_in_bits()}"
    return f"EC {getattr(key, 'curve', '')}".strip()


# --------------------------------------------------------------------------- certificate builder


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _enc_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, raw)


def _enc_oid(oid: str) -> bytes:
    nums = [int(x) for x in oid.split(".")]
    out = bytearray([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out.extend(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _enc_time(moment: datetime) -> bytes:
    moment = moment.astimezone(UTC)
    if moment.year < 2050:
        return _tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())
    return _tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode())


def _enc_name(common_name: str, organization: str | None = None) -> bytes:
    rdns = []
    if organization:
        rdns.append(_tlv(0x31, _seq(_enc_oid("2.5.4.10"), _tlv(0x0C, organization.encode()))))
    rdns.append(_tlv(0x31, _seq(_enc_oid("2.5.4.3"), _tlv(0x0C, common_name.encode()))))
    return _seq(*rdns)


def _ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    crit = _tlv(0x01, b"\xff") if critical else b""
    return _seq(_enc_oid(oid), crit, _tlv(0x04, value))


def _key_id(spki: bytes) -> bytes:
    return hashlib.sha256(spki).digest()[:20]


def generate_key(kind: Literal["ec", "rsa"] = "ec") -> PrivateKey:
    return ECC.generate(curve="P-256") if kind == "ec" else RSA.generate(2048)


def build_certificate(
    *,
    subject_key: PrivateKey,
    common_name: str,
    issuer_key: PrivateKey | None = None,
    issuer: Certificate | None = None,
    organization: str | None = None,
    days: int = 365,
    is_ca: bool = False,
    dns_names: Sequence[str] = (),
    ip_addresses: Sequence[str] = (),
    purposes: Sequence[Literal["server", "client"]] = ("server",),
    not_before: datetime | None = None,
) -> Certificate:
    """A certificate for ``subject_key``, self-signed unless an issuer and its key are given."""
    if (issuer is None) != (issuer_key is None):
        raise ValueError("give both the issuer certificate and its key, or neither")
    signer = issuer_key or subject_key
    start = (not_before or datetime.now(UTC) - timedelta(minutes=5)).replace(microsecond=0)
    spki = bytes(subject_key.public_key().export_key(format="DER"))
    if isinstance(signer, RSA.RsaKey):
        sig_oid, sig_alg = (
            "1.2.840.113549.1.1.11",
            _seq(_enc_oid("1.2.840.113549.1.1.11"), b"\x05\x00"),
        )
    else:
        sig_oid, sig_alg = "1.2.840.10045.4.3.2", _seq(_enc_oid("1.2.840.10045.4.3.2"))
    issuer_name = issuer.subject_der if issuer else _enc_name(common_name, organization)
    issuer_spki = issuer.spki if issuer else spki
    exts = [
        _ext("2.5.29.19", _seq(_tlv(0x01, b"\xff")) if is_ca else _seq(), critical=True),
        _ext(
            "2.5.29.15",
            _tlv(0x03, b"\x01\x06") if is_ca else _tlv(0x03, b"\x05\xa0"),  # keyCertSign+cRLSign
            critical=True,  # or digitalSignature+keyEncipherment
        ),
        _ext("2.5.29.14", _tlv(0x04, _key_id(spki))),
        _ext("2.5.29.35", _seq(_tlv(0x80, _key_id(issuer_spki)))),
    ]
    if not is_ca:
        oids = [EKU_SERVER if p == "server" else EKU_CLIENT for p in purposes]
        exts.append(_ext("2.5.29.37", _seq(*(_enc_oid(o) for o in oids))))
    names = [_tlv(0x82, n.encode("ascii")) for n in dns_names]
    names += [_tlv(0x87, ipaddress.ip_address(ip).packed) for ip in ip_addresses]
    if names:
        exts.append(_ext("2.5.29.17", _seq(*names)))
    tbs = _seq(
        _tlv(0xA0, _enc_int(2)),
        _enc_int(secrets.randbits(63) | 1),
        sig_alg,
        issuer_name,
        _seq(_enc_time(start), _enc_time(start + timedelta(days=days))),
        _enc_name(common_name, organization),
        spki,
        _tlv(0xA3, _seq(*exts)),
    )
    if isinstance(signer, RSA.RsaKey):
        signature = pkcs1_15.new(signer).sign(SHA256.new(tbs))
    else:
        signature = DSS.new(signer, "fips-186-3", encoding="der").sign(SHA256.new(tbs))
    der = _seq(tbs, sig_alg, _tlv(0x03, b"\x00" + signature))
    cert = parse_certificate(der)
    if cert.signature_oid != sig_oid:  # pragma: no cover - defensive
        raise CertificateError("certificate build failed")
    return cert


def describe(cert: Certificate, now: datetime | None = None) -> dict[str, Any]:
    """A JSON-safe summary for the admin API and the console."""
    moment = now or datetime.now(UTC)
    if moment > cert.not_after:
        state = "expired"
    elif moment < cert.not_before:
        state = "not_yet_valid"
    elif cert.not_after - moment < timedelta(days=30):
        state = "expiring"
    else:
        state = "valid"
    return {
        "subject": cert.subject,
        "issuer": cert.issuer,
        "common_name": cert.common_name,
        "serial": format(cert.serial if cert.serial >= 0 else -cert.serial, "x"),
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "key_type": cert.key_type,
        "is_ca": bool(cert.is_ca),
        "dns_names": list(cert.dns_names),
        "status": state,
    }
