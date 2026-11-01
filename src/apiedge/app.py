# Copyright 2026 Alingan Patra
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

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from apiedge import __version__
from apiedge.config import Settings, get_settings
from apiedge.db.base import make_engine, make_session_factory
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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
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
    app.state.secret_box = load_secret_box(settings)
    install_security(app, settings, docs_path=None if settings.is_production else DOCS_URL)

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

    if (STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="console")

    return app
