# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/tenants/{tenant_id}/users``: tenant users and their role assignments.

| Route | Permission |
|---|---|
| ``GET /users``, ``GET /users/{user_id}`` | ``user:read`` |
| ``POST /users`` | ``user:create`` (+ ``role:assign`` when ``role_ids`` are given) |
| ``PATCH /users/{user_id}``, ``POST /users/{user_id}/reset-password`` | ``user:update`` |
| ``DELETE /users/{user_id}`` | ``user:delete`` |
| ``GET /users/{user_id}/roles`` | ``role:read`` |
| ``POST /users/{user_id}/roles``, ``DELETE .../roles/{assignment_id}`` | ``role:assign`` |

Anti-escalation: a caller can only grant roles whose permissions they hold themselves, and can
only manage users whose permissions are a subset of their own (SuperAdmins are exempt).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from apiedge.admin.deps import TenantCaller, forbidden, not_found, require
from apiedge.admin.schemas import (
    AssignmentIn,
    AssignmentOut,
    ResetPasswordIn,
    UserCreate,
    UserOut,
    UserPatch,
)
from apiedge.db.models import Product, Role, RoleAssignment, User, utcnow
from apiedge.security import auth
from apiedge.security.audit import audit
from apiedge.security.passwords import hash_password, password_problems
from apiedge.security.rbac import SUPERADMIN

router = APIRouter(prefix="/tenants/{tenant_id}/users", tags=["users"])


def _out(user: User) -> UserOut:
    out = UserOut.model_validate(user)
    out.is_locked = auth.is_locked(user)
    return out


def _get_user(caller: TenantCaller, user_id: int) -> User:
    # Tenant-bound session: users of other tenants (and platform users) are invisible -> 404.
    user = caller.session.get(User, user_id)
    if user is None or user.tenant_id != caller.tenant_id:
        raise not_found("User not found")
    return user


def _get_role(caller: TenantCaller, role_id: int) -> Role:
    role = caller.session.get(Role, role_id)
    if role is None or role.tenant_id not in (None, caller.tenant_id):
        raise not_found("Role not found")
    if role.name == SUPERADMIN and role.is_builtin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="SuperAdmin is a platform role and not assignable"
        )
    return role


def _check_can_grant(caller: TenantCaller, role: Role) -> None:
    if caller.principal.is_superadmin:
        return
    if not set(role.permissions) <= caller.principal.tenant_permissions(caller.tenant_id):
        raise forbidden()


def _check_can_manage(caller: TenantCaller, target: User) -> None:
    """Callers may not manage users more privileged than themselves."""
    if caller.principal.is_superadmin:
        return
    target_perms = auth.load_principal(target).tenant_permissions(caller.tenant_id)
    if not target_perms <= caller.principal.tenant_permissions(caller.tenant_id):
        raise forbidden()


def _audit(caller: TenantCaller, action: str, user_id: int, **details: object) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="user",
        resource_id=user_id,
        client_ip=caller.ip,
        details=details or None,
    )


@router.get("", response_model=list[UserOut], summary="List users")
def list_users(
    caller: Annotated[TenantCaller, Depends(require("user:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserOut]:
    stmt = select(User).order_by(User.id).limit(limit).offset(offset)
    return [_out(u) for u in caller.session.scalars(stmt)]


@router.post("", response_model=UserOut, status_code=201, summary="Create a user")
def create_user(
    body: UserCreate, caller: Annotated[TenantCaller, Depends(require("user:create"))]
) -> UserOut:
    problems = password_problems(body.password, body.username)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"password": problems})
    roles = [_get_role(caller, rid) for rid in dict.fromkeys(body.role_ids)]
    if roles and not caller.principal.has("role:assign", caller.tenant_id):
        raise forbidden()
    for role in roles:
        _check_can_grant(caller, role)
    user = User(
        tenant_id=caller.tenant_id,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        must_change_password=body.must_change_password,
        is_superadmin=False,
    )
    caller.session.add(user)
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="username already in use") from exc
    for role in roles:
        caller.session.add(
            RoleAssignment(tenant_id=caller.tenant_id, user_id=user.id, role_id=role.id)
        )
    _audit(caller, "user.create", user.id, username=user.username, roles=[r.name for r in roles])
    caller.session.commit()
    return _out(user)


@router.get("/{user_id}", response_model=UserOut, summary="Get a user")
def get_user(
    user_id: int, caller: Annotated[TenantCaller, Depends(require("user:read"))]
) -> UserOut:
    return _out(_get_user(caller, user_id))


@router.patch("/{user_id}", response_model=UserOut, summary="Update, disable or unlock a user")
def update_user(
    user_id: int,
    body: UserPatch,
    caller: Annotated[TenantCaller, Depends(require("user:update"))],
) -> UserOut:
    user = _get_user(caller, user_id)
    _check_can_manage(caller, user)
    changes = body.model_dump(exclude_unset=True)
    if user.id == caller.id and changes.get("is_active") is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="you cannot disable yourself")
    if "email" in changes:
        user.email = body.email
    if body.is_active is not None and body.is_active != user.is_active:
        user.is_active = body.is_active
        if not body.is_active:
            auth.invalidate_sessions(caller.session, user)
    if body.unlock:
        user.locked_until = None
        user.failed_login_count = 0
    if body.reset_mfa:
        user.mfa_enabled = False
        user.mfa_secret_enc = None
        user.mfa_last_step = None
        auth.invalidate_sessions(caller.session, user)
    _audit(caller, "user.update", user.id, **changes)
    caller.session.commit()
    return _out(user)


@router.post(
    "/{user_id}/reset-password",
    status_code=204,
    summary="Set a temporary password (must be changed at next sign-in)",
)
def reset_password(
    user_id: int,
    body: ResetPasswordIn,
    caller: Annotated[TenantCaller, Depends(require("user:update"))],
) -> Response:
    user = _get_user(caller, user_id)
    _check_can_manage(caller, user)
    problems = password_problems(body.new_password, user.username)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"password": problems})
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = True
    user.password_changed_at = utcnow()
    user.locked_until = None
    user.failed_login_count = 0
    auth.invalidate_sessions(caller.session, user)
    _audit(caller, "user.password_reset", user.id)
    caller.session.commit()
    return Response(status_code=204)


@router.delete("/{user_id}", status_code=204, summary="Delete a user")
def delete_user(
    user_id: int, caller: Annotated[TenantCaller, Depends(require("user:delete"))]
) -> Response:
    user = _get_user(caller, user_id)
    if user.id == caller.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="you cannot delete yourself")
    _check_can_manage(caller, user)
    caller.session.delete(user)
    _audit(caller, "user.delete", user_id, username=user.username)
    caller.session.commit()
    return Response(status_code=204)


def _assignment_out(a: RoleAssignment) -> AssignmentOut:
    return AssignmentOut(
        id=a.id,
        tenant_id=a.tenant_id,
        user_id=a.user_id,
        role_id=a.role_id,
        role_name=a.role.name,
        product_id=a.product_id,
        created_at=a.created_at,
    )


@router.get("/{user_id}/roles", response_model=list[AssignmentOut], summary="List role grants")
def list_assignments(
    user_id: int, caller: Annotated[TenantCaller, Depends(require("role:read"))]
) -> list[AssignmentOut]:
    user = _get_user(caller, user_id)
    rows = caller.session.scalars(
        select(RoleAssignment).where(RoleAssignment.user_id == user.id).order_by(RoleAssignment.id)
    )
    return [_assignment_out(a) for a in rows]


@router.post(
    "/{user_id}/roles", response_model=AssignmentOut, status_code=201, summary="Grant a role"
)
def grant_role(
    user_id: int,
    body: AssignmentIn,
    caller: Annotated[TenantCaller, Depends(require("role:assign"))],
) -> AssignmentOut:
    user = _get_user(caller, user_id)
    role = _get_role(caller, body.role_id)
    _check_can_grant(caller, role)
    _check_can_manage(caller, user)
    if body.product_id is not None:
        product = caller.session.get(Product, body.product_id)
        if product is None or product.tenant_id != caller.tenant_id:
            raise not_found("Product not found")
    assignment = RoleAssignment(
        tenant_id=caller.tenant_id, user_id=user.id, role_id=role.id, product_id=body.product_id
    )
    caller.session.add(assignment)
    try:
        caller.session.flush()
    except IntegrityError as exc:
        caller.session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="role already granted") from exc
    auth.invalidate_sessions(caller.session, user)
    _audit(caller, "role.grant", user.id, role=role.name, product_id=body.product_id)
    caller.session.commit()
    caller.session.refresh(assignment)
    return _assignment_out(assignment)


@router.delete("/{user_id}/roles/{assignment_id}", status_code=204, summary="Revoke a role grant")
def revoke_role(
    user_id: int,
    assignment_id: int,
    caller: Annotated[TenantCaller, Depends(require("role:assign"))],
) -> Response:
    user = _get_user(caller, user_id)
    assignment = caller.session.get(RoleAssignment, assignment_id)
    if assignment is None or assignment.user_id != user.id:
        raise not_found("Role grant not found")
    _check_can_grant(caller, assignment.role)
    _check_can_manage(caller, user)
    role_name = assignment.role.name
    caller.session.delete(assignment)
    auth.invalidate_sessions(caller.session, user)
    _audit(caller, "role.revoke", user.id, role=role_name, product_id=assignment.product_id)
    caller.session.commit()
    return Response(status_code=204)
