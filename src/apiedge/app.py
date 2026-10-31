# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application factory.

Layout of the HTTP surface (T-001):

* ``GET /healthz``  - liveness, public, no details (no version disclosure)
* ``GET /readyz``   - readiness (database reachable), public
* ``/api/v1/...``   - admin API (RBAC-protected routers arrive with T-003)
* ``/``             - prebuilt web console from ``apiedge/static``
"""

from __future__ import annotations

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

STATIC_DIR = Path(__file__).resolve().parent / "static"


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
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)

    @app.get("/healthz", tags=["health"], summary="Liveness probe")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"], summary="Readiness probe (database reachable)")
    def readyz(request: Request) -> JSONResponse:
        try:
            with request.app.state.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    if (STATIC_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="console")

    return app
