# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/tenants`` and the audit log.

| Route | Permission |
|---|---|
| ``GET /tenants`` | authenticated; lists the tenants the caller holds ``tenant:read`` in |
| ``POST /tenants`` | ``tenant:create`` (platform) |
| ``GET /tenants/{tenant_id}`` | ``tenant:read`` |
| ``PATCH /tenants/{tenant_id}`` | ``tenant:update`` (``is_active``: SuperAdmins) |
| ``DELETE /tenants/{tenant_id}`` | ``tenant:delete`` (platform) |
| ``GET /tenants/{tenant_id}/audit`` | ``audit:read`` |
| ``GET /audit`` | ``audit:read`` platform-wide (SuperAdmins) |
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apiedge.admin.deps import (
    Caller,
    TenantCaller,
    active_caller,
    forbidden,
    not_found,
    require,
    require_platform,
)
from apiedge.admin.schemas import AuditOut, TenantIn, TenantOut, TenantPatch
from apiedge.db.models import AuditEvent, Tenant
from apiedge.security.audit import audit

router = APIRouter(tags=["tenants"])

Limit = Annotated[int, Query(ge=1, le=200)]
BeforeId = Annotated[int | None, Query(ge=1, description="Return events older than this id")]


@router.get("/tenants", response_model=list[TenantOut], summary="List visible tenants")
def list_tenants(caller: Annotated[Caller, Depends(active_caller)]) -> list[Tenant]:
    p = caller.principal
    if p.is_superadmin:
        return list(caller.session.scalars(select(Tenant).order_by(Tenant.id)))
    if p.tenant_id is None or not p.has("tenant:read", p.tenant_id):
        return []
    tenant = caller.session.get(Tenant, p.tenant_id)
    return [tenant] if tenant else []


@router.post("/tenants", response_model=TenantOut, status_code=201, summary="Create a tenant")
def create_tenant(
    body: TenantIn, caller: Annotated[Caller, Depends(require_platform("tenant:create"))]
) -> Tenant:
    tenant = Tenant(slug=body.slug, name=body.name)
    caller.session.add(tenant)
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="slug already in use") from exc
    audit(
        caller.session,
        "tenant.create",
        tenant_id=tenant.id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="tenant",
        resource_id=tenant.id,
        client_ip=caller.ip,
        details={"slug": tenant.slug},
    )
    caller.session.commit()
    return tenant


@router.get("/tenants/{tenant_id}", response_model=TenantOut, summary="Get a tenant")
def get_tenant(caller: Annotated[TenantCaller, Depends(require("tenant:read"))]) -> Tenant:
    return caller.tenant


@router.patch("/tenants/{tenant_id}", response_model=TenantOut, summary="Update a tenant")
def update_tenant(
    body: TenantPatch, caller: Annotated[TenantCaller, Depends(require("tenant:update"))]
) -> Tenant:
    tenant = caller.tenant
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if "is_active" in changes and not caller.principal.has("tenant:delete", None):
        raise forbidden()  # suspending a tenant is a platform decision
    for key, value in changes.items():
        setattr(tenant, key, value)
    audit(
        caller.session,
        "tenant.update",
        tenant_id=tenant.id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="tenant",
        resource_id=tenant.id,
        client_ip=caller.ip,
        details=changes,
    )
    caller.session.commit()
    return tenant


@router.delete("/tenants/{tenant_id}", status_code=204, summary="Delete a tenant and its data")
def delete_tenant(
    tenant_id: int, caller: Annotated[Caller, Depends(require_platform("tenant:delete"))]
) -> Response:
    tenant = caller.session.get(Tenant, tenant_id)
    if tenant is None:
        raise not_found("Tenant not found")
    caller.session.delete(tenant)
    audit(
        caller.session,
        "tenant.delete",
        tenant_id=tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="tenant",
        resource_id=tenant_id,
        client_ip=caller.ip,
        details={"slug": tenant.slug},
    )
    caller.session.commit()
    return Response(status_code=204)


def _audit_page(
    session: Session, limit: int, before_id: int | None, action: str | None
) -> list[AuditEvent]:
    stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if before_id is not None:
        stmt = stmt.where(AuditEvent.id < before_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    return list(session.scalars(stmt))


@router.get(
    "/tenants/{tenant_id}/audit",
    response_model=list[AuditOut],
    tags=["audit"],
    summary="Tenant audit log (newest first)",
)
def tenant_audit(
    caller: Annotated[TenantCaller, Depends(require("audit:read"))],
    limit: Limit = 50,
    before_id: BeforeId = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
) -> list[AuditEvent]:
    # The session is tenant-bound: only this tenant's events are visible.
    return _audit_page(caller.session, limit, before_id, action)


@router.get(
    "/audit",
    response_model=list[AuditOut],
    tags=["audit"],
    summary="Platform audit log, all tenants (SuperAdmins)",
)
def platform_audit(
    caller: Annotated[Caller, Depends(require_platform("audit:read"))],
    limit: Limit = 50,
    before_id: BeforeId = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    tenant_id: Annotated[int | None, Query(ge=1)] = None,
) -> list[AuditEvent]:
    stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if before_id is not None:
        stmt = stmt.where(AuditEvent.id < before_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if tenant_id is not None:
        stmt = stmt.where(AuditEvent.tenant_id == tenant_id)
    return list(caller.session.scalars(stmt))
