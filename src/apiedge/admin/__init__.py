# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Admin API (``/api/v1``). Every route declares its RBAC dependency (see ``admin.deps``)."""

from __future__ import annotations

from fastapi import APIRouter

from apiedge.admin import (
    analytics,
    apis,
    auth_routes,
    inspector,
    policies,
    products,
    roles,
    system,
    tenants,
    users,
)
from apiedge.admin.deps import annotate_access


def build_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")
    for module in (
        auth_routes,
        tenants,
        users,
        roles,
        products,
        apis,
        policies,
        analytics,
        inspector,
        system,
    ):
        # Publish each operation's permission as ``x-apiedge-access`` in the OpenAPI document.
        annotate_access(module.router.routes)
        api.include_router(module.router)
    return api


__all__ = ["build_router"]
