# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Native TLS for the console and gateway listeners (T-023, ADR 0013).

* :func:`server_context` builds the listener's ``SSLContext``: TLS 1.2 or 1.3 minimum, forward
  secret AEAD ciphers by default, no compression or renegotiation, optional client
  certificates checked against a CA bundle.
* :class:`TlsInfoProtocol` is uvicorn's h11 protocol plus the ASGI TLS extension
  (``scope["extensions"]["tls"]["client_cert_chain"]``), so the gateway's ``mtls`` policy can
  see the client certificate of the connection.
* :func:`cert_from_header` reads a client certificate forwarded by a TLS-terminating proxy.
"""

from __future__ import annotations

import base64
import binascii
import ssl
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from uvicorn.protocols.http.h11_impl import H11Protocol

from apiedge.security.x509 import MAX_CERT_BYTES, PEM_CERT_RE

DEFAULT_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!SHA1"
_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}

Scope = MutableMapping[str, Any]
ASGIApp = Callable[[Scope, Any, Any], Awaitable[None]]


def server_context(
    cert_file: Path,
    key_file: Path,
    *,
    password: str | None = None,
    min_version: str = "1.2",
    ciphers: str | None = None,
    client_auth: str = "none",
    client_ca_file: Path | None = None,
) -> ssl.SSLContext:
    """The listener's TLS context (raises ``ssl.SSLError`` / ``OSError`` on bad files)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _VERSIONS[min_version]
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.set_ciphers(ciphers or DEFAULT_CIPHERS)  # TLS 1.3 suites are always the safe defaults
    ctx.load_cert_chain(str(cert_file), str(key_file), password=password)
    if client_auth != "none":
        if client_ca_file is None:
            raise ValueError("client certificates need a CA bundle")
        ctx.load_verify_locations(cafile=str(client_ca_file))
        ctx.verify_mode = ssl.CERT_REQUIRED if client_auth == "required" else ssl.CERT_OPTIONAL
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def uvicorn_tls_options(settings: Any, *, gateway: bool) -> dict[str, Any]:
    """Keyword arguments for ``uvicorn.Config`` enabling TLS on one listener (or none)."""
    prefix = "gateway_tls" if gateway else "tls"
    cert: Path | None = getattr(settings, f"{prefix}_cert_file")
    key: Path | None = getattr(settings, f"{prefix}_key_file")
    if cert is None or key is None:
        return {}
    secret = getattr(settings, f"{prefix}_key_password")
    password = secret.get_secret_value() if secret is not None else None
    ctx = server_context(
        cert,
        key,
        password=password,
        min_version=settings.tls_min_version,
        ciphers=settings.tls_ciphers,
        client_auth=settings.gateway_tls_client_auth if gateway else "none",
        client_ca_file=settings.gateway_tls_client_ca_file if gateway else None,
    )
    options: dict[str, Any] = {
        "ssl_certfile": str(cert),  # marks the config as TLS (https scheme)
        "ssl_context_factory": lambda _config, _default: ctx,
    }
    if gateway:
        options["http"] = TlsInfoProtocol
    return options


def tls_extension(ssl_object: Any) -> dict[str, Any]:
    """The ASGI TLS extension for one connection."""
    der = None
    try:
        der = ssl_object.getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        der = None
    version = ssl_object.version() if hasattr(ssl_object, "version") else None
    return {
        "server_cert": None,
        "client_cert_chain": [ssl.DER_cert_to_PEM_cert(der)] if der else [],
        "client_cert_name": None,
        "client_cert_error": None,
        "tls_version": {"TLSv1.2": 0x0303, "TLSv1.3": 0x0304}.get(version or ""),
        "cipher_suite": None,
    }


class TlsInfoProtocol(H11Protocol):
    """uvicorn's h11 protocol that adds the ASGI TLS extension to every request scope."""

    def connection_made(self, transport: Any) -> None:
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return
        extension = tls_extension(ssl_object)
        inner: ASGIApp = self.app

        async def with_tls(scope: Scope, receive: Any, send: Any) -> None:
            if scope.get("type") in ("http", "websocket"):
                extensions = {**(scope.get("extensions") or {}), "tls": extension}
                scope = {**scope, "extensions": extensions}
            await inner(scope, receive, send)

        self.app = with_tls


def cert_from_scope(scope: Scope) -> bytes | None:
    """DER of the client certificate presented on this TLS connection, if any."""
    tls = (scope.get("extensions") or {}).get("tls") or {}
    chain = tls.get("client_cert_chain") or []
    if not chain or not isinstance(chain[0], str):
        return None
    try:
        return ssl.PEM_cert_to_DER_cert(chain[0])
    except ValueError:
        return None


def cert_from_header(value: str) -> bytes | None:
    """DER of a forwarded client certificate: URL-encoded PEM (nginx, Envoy ``Cert=``) or
    base64 DER. None when unreadable."""
    if not value or len(value) > 4 * MAX_CERT_BYTES:
        return None
    text = value
    if "Cert=" in text:  # Envoy x-forwarded-client-cert: By=...;Hash=...;Cert="<url-pem>"
        text = text.split("Cert=", 1)[1].split(";", 1)[0].strip('"')
    text = unquote(text)
    match = PEM_CERT_RE.search(text)
    raw = match.group(1) if match else text
    try:
        der = base64.b64decode("".join(raw.split()), validate=True)
    except (ValueError, binascii.Error):
        return None
    return der if 0 < len(der) <= MAX_CERT_BYTES else None
