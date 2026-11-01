# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Admin API (``/api/v1``). Every route declares its RBAC dependency (see ``admin.deps``)."""

from __future__ import annotations

from fastapi import APIRouter

from apiedge.admin import auth_routes, products, roles, system, tenants, users


def build_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")
    api.include_router(auth_routes.router)
    api.include_router(tenants.router)
    api.include_router(users.router)
    api.include_router(roles.router)
    api.include_router(products.router)
    api.include_router(system.router)
    return api


__all__ = ["build_router"]
