# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""HTTP hardening middleware for the console / admin API (T-002, OWASP A01, A04, A05, A08, A09).

All classes are pure ASGI middleware (no ``BaseHTTPMiddleware``), so they also cover streaming
responses. :func:`install_security` wires them in this order (outermost first)::

    SecurityHeaders -> RequestContext (request id, access log, error barrier)
        -> CORS (allow-list) -> BodySizeLimit -> CSRF -> application

so even 413/403/500 responses carry the security headers and a request id.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import secrets
import time
import uuid
from collections.abc import Iterable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import cookie_parser
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from apiedge.config import Settings
from apiedge.logs import request_id_var

log = logging.getLogger("apiedge.security")
access_log = logging.getLogger("apiedge.access")

# Cookie names T-003 uses for browser sessions. Requests carrying one of them are
# "cookie-authenticated" and must pass the CSRF check on unsafe methods.
AUTH_COOKIE_NAMES = ("apiedge_session", "apiedge_refresh")
CSRF_COOKIE_NAME = "apiedge_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
REQUEST_ID_HEADER = "x-request-id"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

CONSOLE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
# Swagger UI (development only) loads its bundle from jsDelivr and uses an inline bootstrap script.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

_REQUEST_ID_OK = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


async def _send_json(send: Send, status: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class SecurityHeadersMiddleware:
    """Adds HSTS (HTTPS only), CSP, nosniff, framing, referrer and isolation headers."""

    def __init__(
        self, app: ASGIApp, *, hsts_max_age: int = 31_536_000, docs_path: str | None = None
    ) -> None:
        self.app = app
        self.hsts_max_age = hsts_max_age
        self.docs_path = docs_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        is_https = scope.get("scheme") == "https"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h.setdefault("X-Content-Type-Options", "nosniff")
                h.setdefault("X-Frame-Options", "DENY")
                h.setdefault("Referrer-Policy", "no-referrer")
                h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
                # Only same-origin (CORP) subresources may load (ZAP 90004, T-018).
                h.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
                h.setdefault(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                )
                csp = DOCS_CSP if self.docs_path and path == self.docs_path else CONSOLE_CSP
                h.setdefault("Content-Security-Policy", csp)
                if path.startswith("/api/") or path in ("/healthz", "/readyz"):
                    h.setdefault("Cache-Control", "no-store")
                if is_https and self.hsts_max_age > 0:
                    h.setdefault(
                        "Strict-Transport-Security",
                        f"max-age={self.hsts_max_age}; includeSubDomains",
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RequestContextMiddleware:
    """Request id, structured access log and the global error barrier (no stack traces leak)."""

    def __init__(self, app: ASGIApp, *, expose_errors: bool = False) -> None:
        self.app = app
        self.expose_errors = expose_errors

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(REQUEST_ID_HEADER.encode())
        rid = incoming.decode("latin-1") if incoming else ""
        if not _REQUEST_ID_OK.match(rid):
            rid = uuid.uuid4().hex
        token = request_id_var.set(rid)
        started = False
        status = 500
        t0 = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = int(message["status"])
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            log.exception("unhandled error", extra={"path": scope.get("path", "")})
            if started:
                raise
            body: dict[str, Any] = {"detail": "Internal server error", "request_id": rid}
            if self.expose_errors:  # development only: type and message, never a traceback
                body["error"] = f"{type(exc).__name__}: {exc}"
            await _send_json(send_wrapper, 500, body)
        finally:
            client = scope.get("client")
            access_log.info(
                "request",
                extra={
                    "method": scope.get("method"),
                    "path": scope.get("path"),  # query string deliberately omitted
                    "status": status,
                    "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "client": client[0] if client else None,
                },
            )
            request_id_var.reset(token)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Rejects bodies over ``max_bytes`` with 413, by Content-Length and while streaming."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                await _send_json(send, 400, {"detail": "Invalid Content-Length"})
                return
            if length > self.max_bytes:
                await _send_json(send, 413, {"detail": "Request body too large"})
                return

        received = 0
        started = False
        rejected = False  # we already answered 413; drop whatever the app sends afterwards

        async def limited_receive() -> Message:
            nonlocal received, started, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Answer here: frameworks may turn exceptions raised while reading the body
                    # into their own 400, so we cannot rely on catching it further out.
                    if not started:
                        started = rejected = True
                        await _send_json(send, 413, {"detail": "Request body too large"})
                    raise _BodyTooLargeError
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if rejected:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except Exception:
            if not rejected:
                raise


class CSRFMiddleware:
    """Double-submit-cookie CSRF protection plus Origin check for cookie-authenticated requests.

    * Every response to a client without the ``apiedge_csrf`` cookie sets one (random, readable by
      the console's JavaScript, ``SameSite=Strict``; ``Secure`` over HTTPS).
    * An unsafe request (POST/PUT/PATCH/DELETE ...) that carries an auth cookie must send the same
      value in the ``X-CSRF-Token`` header, and its ``Origin`` (if sent) must be this server or an
      allow-listed origin. Bearer-token clients without auth cookies are not affected.
    """

    def __init__(self, app: ASGIApp, *, trusted_origins: Iterable[str] = ()) -> None:
        self.app = app
        self.trusted_origins = frozenset(o.rstrip("/").lower() for o in trusted_origins)

    def _origin_ok(self, scope: Scope, origin: str) -> bool:
        origin = origin.rstrip("/").lower()
        if origin in self.trusted_origins:
            return True
        host = dict(scope.get("headers") or []).get(b"host", b"").decode("latin-1").lower()
        return bool(host) and origin == f"{scope.get('scheme', 'http')}://{host}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        cookies = cookie_parser(headers.get(b"cookie", b"").decode("latin-1"))
        csrf_cookie = cookies.get(CSRF_COOKIE_NAME, "")

        if scope.get("method", "GET") not in SAFE_METHODS and any(
            cookies.get(name) for name in AUTH_COOKIE_NAMES
        ):
            origin = headers.get(b"origin")
            sent = headers.get(CSRF_HEADER_NAME.encode(), b"").decode("latin-1")
            if origin is not None and not self._origin_ok(scope, origin.decode("latin-1")):
                log.warning("csrf: untrusted origin", extra={"path": scope.get("path")})
                await _send_json(send, 403, {"detail": "CSRF validation failed"})
                return
            if not csrf_cookie or not sent or not hmac.compare_digest(sent, csrf_cookie):
                log.warning("csrf: token missing or mismatched", extra={"path": scope.get("path")})
                await _send_json(send, 403, {"detail": "CSRF validation failed"})
                return

        if csrf_cookie:
            await self.app(scope, receive, send)
            return

        new_token = secrets.token_urlsafe(32)
        secure = "; Secure" if scope.get("scheme") == "https" else ""

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).append(
                    "set-cookie",
                    f"{CSRF_COOKIE_NAME}={new_token}; Path=/; SameSite=Strict{secure}",
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)


async def _validation_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """422 without echoing submitted values (``input``), which may contain passwords."""
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    safe = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in errors]
    return JSONResponse({"detail": safe}, status_code=422)


def install_security(app: FastAPI, settings: Settings, *, docs_path: str | None) -> None:
    """Register the hardening middleware and error handlers on ``app``."""
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    # add_middleware: the last one added is the outermost.
    app.add_middleware(CSRFMiddleware, trusted_origins=settings.cors_allow_origins)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
            expose_headers=["X-Request-ID"],
            max_age=600,
        )
    app.add_middleware(RequestContextMiddleware, expose_errors=not settings.is_production)
    app.add_middleware(
        SecurityHeadersMiddleware, hsts_max_age=settings.hsts_max_age, docs_path=docs_path
    )
