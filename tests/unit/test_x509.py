# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""X.509 parsing, path validation and keys (T-023), the TLS helpers and TLS settings."""

from __future__ import annotations

import base64
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from apiedge.cli import main
from apiedge.config import Settings
from apiedge.security import x509
from apiedge.security.tls import cert_from_header, cert_from_scope, tls_extension

NOW = datetime.now(UTC)


@pytest.fixture(scope="module")
def chain() -> dict[str, Any]:
    root_key, inter_key, leaf_key = (
        x509.generate_key(),
        x509.generate_key("rsa"),
        x509.generate_key(),
    )
    root = x509.build_certificate(
        subject_key=root_key, common_name="Root", organization="Org, Inc", is_ca=True
    )
    inter = x509.build_certificate(
        subject_key=inter_key, common_name="Issuing", issuer=root, issuer_key=root_key, is_ca=True
    )
    leaf = x509.build_certificate(
        subject_key=leaf_key,
        common_name="svc",
        issuer=inter,
        issuer_key=inter_key,
        purposes=("client", "server"),
        dns_names=["svc.example"],
        ip_addresses=["10.1.2.3", "::1"],
    )
    return {"root": root, "inter": inter, "leaf": leaf, "leaf_key": leaf_key, "root_key": root_key}


def test_parse_fields(chain: dict[str, Any]) -> None:
    root, leaf = chain["root"], chain["leaf"]
    assert root.subject == "CN=Root,O=Org\\, Inc" and root.common_name == "Root"
    assert root.is_ca and root.key_cert_sign and root.is_self_issued
    assert leaf.issuer == "CN=Issuing" and leaf.is_ca is False
    assert leaf.dns_names == ("svc.example",) and leaf.ip_addresses == ("10.1.2.3", "::1")
    assert leaf.extended_key_usage == {x509.EKU_CLIENT, x509.EKU_SERVER}
    assert chain["inter"].key_type == "RSA 2048" and leaf.key_type.startswith("EC")
    assert leaf.version == 3 and leaf.serial > 0
    # The standard library reads what we build.
    decoded = ssl.DER_cert_to_PEM_cert(leaf.der)
    assert x509.load_pem_certificates(decoded)[0].fingerprint_sha256 == leaf.fingerprint_sha256


def test_chain_validation(chain: dict[str, Any]) -> None:
    root, inter, leaf = chain["root"], chain["inter"], chain["leaf"]
    assert x509.verify_chain(leaf, [root], intermediates=[inter]) is None
    assert x509.verify_chain(leaf, [inter]) is None  # intermediate as anchor
    assert x509.verify_chain(leaf, [root]) == "not issued by a trusted certificate"
    assert x509.verify_chain(leaf, [leaf]) is None  # pinned
    assert x509.verify_chain(leaf, [root], intermediates=[inter], now=NOW + timedelta(days=400))
    assert x509.verify_chain(leaf, [inter], now=NOW - timedelta(days=1)) == "not yet valid"
    # A non-CA certificate cannot issue, even when its key signed the leaf.
    key = x509.generate_key()
    fake_ca = x509.build_certificate(subject_key=key, common_name="Fake")
    child = x509.build_certificate(
        subject_key=x509.generate_key(),
        common_name="c",
        issuer=fake_ca,
        issuer_key=key,
        purposes=("client",),
    )
    assert x509.verify_chain(child, [fake_ca]) == "not issued by a trusted certificate"
    # Same subject, different key: signature check fails.
    twin = x509.build_certificate(
        subject_key=x509.generate_key(), common_name="Issuing", is_ca=True
    )
    assert x509.verify_chain(leaf, [twin]) == "not issued by a trusted certificate"
    server_only = x509.build_certificate(
        subject_key=x509.generate_key(),
        common_name="s",
        issuer=root,
        issuer_key=chain["root_key"],
        purposes=("server",),
    )
    assert x509.verify_chain(server_only, [root], purpose="client") == (
        "not valid for client authentication"
    )
    assert x509.verify_chain(server_only, [root], purpose="server") is None


def test_tampered_and_malformed_certificates(chain: dict[str, Any]) -> None:
    leaf = chain["leaf"]
    der = bytearray(leaf.der)
    der[-5] ^= 0xFF  # signature byte
    tampered = x509.parse_certificate(bytes(der))
    assert not x509.verify_signature(tampered, chain["inter"])
    for bad in (
        b"",
        b"\x30\x03\x02\x01",
        leaf.der + b"\x00",
        b"\x30\x84\xff\xff\xff\xff",
        b"\x1f\x00",
        b"\x30" + b"\x82\x01\x00" + b"\x00" * 10,
    ):
        with pytest.raises(x509.CertificateError):
            x509.parse_certificate(bad)
    with pytest.raises(x509.CertificateError):
        x509.parse_certificate(b"\x30\x82" + (20000).to_bytes(2, "big") + b"\x00" * 20000)
    with pytest.raises(x509.CertificateError, match="no PEM"):
        x509.load_pem_certificates("hello")
    with pytest.raises(x509.CertificateError, match="at most"):
        x509.load_pem_certificates(leaf.pem() * 3, limit=2)
    with pytest.raises(x509.CertificateError, match="certificate 1"):
        x509.load_pem_certificates("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----")


def test_private_keys(chain: dict[str, Any], tmp_path: Path) -> None:
    key = chain["leaf_key"]
    pem = x509.private_key_pem(key)
    assert "BEGIN PRIVATE KEY" in pem
    assert x509.key_matches(chain["leaf"], x509.load_private_key(pem))
    assert not x509.key_matches(chain["root"], key)
    rsa = x509.generate_key("rsa")
    assert x509.load_private_key(x509.private_key_pem(rsa)).size_in_bits() == 2048
    assert x509.describe_key(rsa) == "RSA 2048"
    enc = rsa.export_key(
        format="PEM",
        passphrase="pw-123456",
        pkcs=8,
        protection="PBKDF2WithHMAC-SHA512AndAES256-CBC",
    ).decode()
    assert x509.load_private_key(enc, "pw-123456").has_private()
    with pytest.raises(x509.CertificateError):
        x509.load_private_key(enc, "wrong")
    with pytest.raises(x509.CertificateError, match="public key"):
        x509.load_private_key(key.public_key().export_key(format="PEM"))
    with pytest.raises(x509.CertificateError):
        x509.load_private_key("x" * 70000)


def test_describe_status(chain: dict[str, Any]) -> None:
    leaf = chain["leaf"]
    assert x509.describe(leaf)["status"] == "valid"
    assert x509.describe(leaf, leaf.not_after - timedelta(days=3))["status"] == "expiring"
    assert x509.describe(leaf, leaf.not_after + timedelta(days=1))["status"] == "expired"
    assert x509.describe(leaf, leaf.not_before - timedelta(days=1))["status"] == "not_yet_valid"


def test_client_certificate_from_header_and_scope(chain: dict[str, Any]) -> None:
    leaf = chain["leaf"]
    pem = leaf.pem()
    assert cert_from_header(quote(pem)) == leaf.der  # nginx $ssl_client_escaped_cert
    assert cert_from_header(f'By=spiffe://x;Hash=ab;Cert="{quote(pem)}";Subject="CN=x"') == leaf.der
    assert cert_from_header(base64.b64encode(leaf.der).decode()) == leaf.der
    for bad in ("", "%%%", "not base64!", "A" * 100_000):
        assert cert_from_header(bad) is None
    scope = {"extensions": {"tls": {"client_cert_chain": [pem]}}}
    assert cert_from_scope(scope) == leaf.der
    assert cert_from_scope({}) is None
    assert cert_from_scope({"extensions": {"tls": {"client_cert_chain": []}}}) is None

    class Obj:
        def getpeercert(self, binary_form: bool = False) -> bytes:
            return bytes(leaf.der)

        def version(self) -> str:
            return "TLSv1.3"

    ext = tls_extension(Obj())
    assert (
        ext["tls_version"] == 0x0304 and cert_from_scope({"extensions": {"tls": ext}}) == leaf.der
    )


def test_tls_settings_validation(tmp_path: Path) -> None:
    f = tmp_path / "x.pem"
    with pytest.raises(ValidationError, match="or neither"):
        Settings(tls_cert_file=f)
    with pytest.raises(ValidationError, match="needs gateway TLS"):
        Settings(gateway_tls_client_auth="optional")
    with pytest.raises(ValidationError, match="CLIENT_CA_FILE"):
        Settings(
            gateway_tls_cert_file=f, gateway_tls_key_file=f, gateway_tls_client_auth="required"
        )
    with pytest.raises(ValidationError):
        Settings(gateway_client_cert_header="x-cert\r\nfoo")
    with pytest.raises(ValidationError):
        Settings(tls_ciphers="ALL; rm -rf")
    s = Settings(tls_cert_file=f, tls_key_file=f, gateway_client_cert_header="X-Client-Cert")
    assert s.console_tls and not s.gateway_tls and s.gateway_client_cert_header == "x-client-cert"
    assert Settings().tls_min_version == "1.2" and Settings().gateway_tls_client_auth == "none"


def test_cli_self_signed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "tls"
    assert (
        main(
            [
                "tls",
                "self-signed",
                "--out-dir",
                str(out),
                "--host",
                "gw.example",
                "--host",
                "192.0.2.1",
            ]
        )
        == 0
    )
    cert = x509.load_pem_certificates((out / "apiedge-cert.pem").read_text())[0]
    assert cert.dns_names == ("gw.example",) and "192.0.2.1" in cert.ip_addresses
    key = x509.load_private_key((out / "apiedge-key.pem").read_text())
    assert x509.key_matches(cert, key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(out / "apiedge-cert.pem", out / "apiedge-key.pem")
    assert main(["tls", "self-signed", "--out-dir", str(out)]) == 1  # exists
    assert main(["tls", "self-signed", "--out-dir", str(out), "--force"]) == 0
    assert main(["tls", "self-signed", "--out-dir", str(out), "--force", "--host", "a b"]) == 2
    assert "fingerprint" in capsys.readouterr().out
