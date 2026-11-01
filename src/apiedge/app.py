# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application factory.

Layout of the HTTP surface (T-001):

* ``GET /healthz``  - liveness, public, no details (no version disclosure)
* ``GET /readyz``   - readiness (database reachable), public
* ``/api/v1/...``   - admin API (RBAC-protected routers arrive with T-003)
* ``/``             - prebuilt web console from ``apiedge/static``

Every response passes the T-002 hardening stack (``apiedge.security.middleware``).
"""

from __future__ import annotations

import hmac
import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from apiedge import __version__
from apiedge.admin import build_router
from apiedge.analytics.metrics import MetricsCollector
from apiedge.config import Settings, get_settings
from apiedge.db.base import make_engine, make_session_factory
from apiedge.gateway.bus import ConfigBus, build_bus, install_change_notifier
from apiedge.security.auth import LoginThrottle, TokenSigner
from apiedge.security.crypto import KeyConfigError, SecretBox, build_secret_box
from apiedge.security.middleware import install_security

STATIC_DIR = Path(__file__).resolve().parent / "static"
DOCS_URL = "/api/docs"

log = logging.getLogger("apiedge")


def load_secret_box(settings: Settings) -> SecretBox | None:
    """The secrets-encryption box, or None (with a warning) if no master key is configured."""
    try:
        return build_secret_box(
            settings.secret_key.get_secret_value() if settings.secret_key else None,
            settings.effective_secret_key_file,
            [k.get_secret_value() for k in settings.secret_key_previous],
        )
    except KeyConfigError as exc:
        log.warning("secrets encryption unavailable: %s", exc)
        return None


def jwt_signing_key(settings: Settings, box: SecretBox | None) -> bytes:
    """Access-token key: APIEDGE_JWT_SECRET, else derived from the master key, else ephemeral."""
    if settings.jwt_secret is not None:
        return settings.jwt_secret.get_secret_value().encode("utf-8")
    if box is not None:
        return box.derive_key("jwt-access-v1")
    log.warning("no secrets master key: console sessions will not survive a restart")
    return secrets.token_bytes(32)


def create_app(
    settings: Settings | None = None,
    bus: ConfigBus | None = None,
    metrics: MetricsCollector | None = None,
) -> FastAPI:
    """The console and admin API app. ``bus`` carries config change events to the gateway;
    ``metrics`` is the gateway's collector, exposed at ``/metrics`` (same process only)."""
    settings = settings or get_settings()
    if bus is None:
        redis_url = settings.redis_url.get_secret_value() if settings.redis_url else None
        bus = build_bus(redis_url)
    engine = make_engine(settings.effective_database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="APIEdge Admin API",
        version=__version__,
        lifespan=lifespan,
        # Interactive docs only in development; the OpenAPI JSON stays available.
        docs_url=None if settings.is_production else DOCS_URL,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.config_bus = bus
    app.state.metrics = metrics or MetricsCollector()
    # Gateway hot reload (T-007): committed API/product/tenant changes publish an event.
    install_change_notifier(app.state.session_factory, bus)
    app.state.secret_box = load_secret_box(settings)
    app.state.token_signer = TokenSigner(
        jwt_signing_key(settings, app.state.secret_box), settings.access_token_ttl_seconds
    )
    app.state.login_throttle = LoginThrottle(settings.login_rate_limit_per_minute)
    install_security(app, settings, docs_path=None if settings.is_production else DOCS_URL)
    app.include_router(build_router())

    @app.get("/healthz", tags=["health"], summary="Liveness probe")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"], summary="Readiness probe (database reachable)")
    def readyz(request: Request) -> JSONResponse:
        try:
            with request.app.state.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            log.warning("readiness check failed: database unreachable", exc_info=True)
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    @app.get("/metrics", include_in_schema=False)
    def prometheus_metrics(request: Request) -> Response:
        """Prometheus scrape endpoint (T-013): off unless APIEDGE_METRICS_TOKEN is set."""
        token = settings.metrics_token
        if token is None:
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
        expected = token.get_secret_value().encode("utf-8")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            supplied.strip().encode("utf-8"), expected
        ):
            return JSONResponse(
                {"detail": "not_authenticated"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return PlainTextResponse(
            request.app.state.metrics.prometheus_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
            headers={"cache-control": "no-store"},
        )

    if (STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="console")

    return app
