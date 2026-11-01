# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Permission catalog and ``/api/v1/tenants/{tenant_id}/roles``.

| Route | Permission |
|---|---|
| ``GET /permissions`` | authenticated |
| ``GET /tenants/{tenant_id}/roles``, ``GET .../roles/{role_id}`` | ``role:read`` |
| ``POST /tenants/{tenant_id}/roles`` | ``role:create`` |
| ``PATCH /tenants/{tenant_id}/roles/{role_id}`` | ``role:update`` |
| ``DELETE /tenants/{tenant_id}/roles/{role_id}`` | ``role:delete`` |

Built-in roles are global and read-only. Custom roles belong to one tenant and may contain only
tenant permissions the caller holds.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from apiedge.admin.deps import Caller, TenantCaller, active_caller, forbidden, not_found, require
from apiedge.admin.schemas import PermissionOut, RoleIn, RoleOut, RolePatch
from apiedge.db.models import Role, RoleAssignment, RolePermission
from apiedge.security.audit import audit
from apiedge.security.rbac import PERMISSIONS, PLATFORM_PERMISSIONS

router = APIRouter(tags=["roles"])


@router.get("/permissions", response_model=list[PermissionOut], summary="Permission catalog")
def list_permissions(_caller: Annotated[Caller, Depends(active_caller)]) -> list[PermissionOut]:
    return [
        PermissionOut(name=n, description=d, platform_only=n in PLATFORM_PERMISSIONS)
        for n, d in PERMISSIONS.items()
    ]


def _get_role(caller: TenantCaller, role_id: int, *, writable: bool = False) -> Role:
    role = caller.session.get(Role, role_id)
    if role is None or role.tenant_id not in (None, caller.tenant_id):
        raise not_found("Role not found")
    if writable and (role.is_builtin or role.tenant_id is None):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="built-in roles are read-only")
    return role


def _check_subset(caller: TenantCaller, permissions: list[str]) -> None:
    if caller.principal.is_superadmin:
        return
    if not set(permissions) <= caller.principal.tenant_permissions(caller.tenant_id):
        raise forbidden()


def _audit(caller: TenantCaller, action: str, role: Role, **details: object) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="role",
        resource_id=role.id,
        client_ip=caller.ip,
        details={"name": role.name, **details},
    )


@router.get("/tenants/{tenant_id}/roles", response_model=list[RoleOut], summary="List roles")
def list_roles(caller: Annotated[TenantCaller, Depends(require("role:read"))]) -> list[Role]:
    # Tenant-bound session: built-in roles plus this tenant's custom roles.
    stmt = select(Role).order_by(Role.is_builtin.desc(), Role.name)
    return list(caller.session.scalars(stmt))


@router.post(
    "/tenants/{tenant_id}/roles", response_model=RoleOut, status_code=201, summary="Create a role"
)
def create_role(
    body: RoleIn, caller: Annotated[TenantCaller, Depends(require("role:create"))]
) -> Role:
    _check_subset(caller, body.permissions)
    role = Role(
        tenant_id=caller.tenant_id,
        name=body.name,
        description=body.description,
        is_builtin=False,
        permission_rows=[RolePermission(permission=p) for p in body.permissions],
    )
    caller.session.add(role)
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="role name already in use") from exc
    _audit(caller, "role.create", role, permissions=body.permissions)
    caller.session.commit()
    return role


@router.get("/tenants/{tenant_id}/roles/{role_id}", response_model=RoleOut, summary="Get a role")
def get_role(role_id: int, caller: Annotated[TenantCaller, Depends(require("role:read"))]) -> Role:
    return _get_role(caller, role_id)


@router.patch(
    "/tenants/{tenant_id}/roles/{role_id}", response_model=RoleOut, summary="Update a custom role"
)
def update_role(
    role_id: int, body: RolePatch, caller: Annotated[TenantCaller, Depends(require("role:update"))]
) -> Role:
    role = _get_role(caller, role_id, writable=True)
    _check_subset(caller, role.permissions)  # cannot edit roles more privileged than oneself
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if body.name is not None:
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.permissions is not None:
        _check_subset(caller, body.permissions)
        role.permission_rows = [
            RolePermission(role_id=role.id, permission=p) for p in body.permissions
        ]
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="role name already in use") from exc
    _audit(caller, "role.update", role, **changes)
    caller.session.commit()
    return role


@router.delete(
    "/tenants/{tenant_id}/roles/{role_id}", status_code=204, summary="Delete a custom role"
)
def delete_role(
    role_id: int, caller: Annotated[TenantCaller, Depends(require("role:delete"))]
) -> Response:
    role = _get_role(caller, role_id, writable=True)
    _check_subset(caller, role.permissions)
    in_use = caller.session.scalar(
        select(RoleAssignment.id).where(RoleAssignment.role_id == role.id).limit(1)
    )
    if in_use is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="role is still granted to users")
    _audit(caller, "role.delete", role)
    caller.session.delete(role)
    caller.session.commit()
    return Response(status_code=204)
