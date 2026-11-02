# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""FastAPI dependencies: database session, authentication and RBAC (T-003).

Every admin route depends on exactly one of

* :func:`authenticated` - any signed-in user (own profile, password change, MFA),
* :func:`require_platform` - a platform permission (SuperAdmins only),
* :func:`require` - a tenant permission for the ``{tenant_id}`` in the path. It answers 404 for
  tenants the caller does not belong to (no existence disclosure), 403 for a missing
  permission, and binds the session to the tenant so every query is tenant-filtered.
* :func:`require_any` - like :func:`require`, but a product-scoped grant of the permission is
  enough to pass; the route must then check the permission for the product it touches
  (``Principal.has(permission, tenant_id, product_id)``), as ``admin.products`` does.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Path, Request, status
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

from apiedge.config import Settings
from apiedge.db.models import Tenant, User
from apiedge.db.tenancy import bind_tenant
from apiedge.security.auth import AuthError, TokenSigner, load_principal
from apiedge.security.middleware import AUTH_COOKIE_NAMES
from apiedge.security.rbac import PERMISSIONS, Principal

SESSION_COOKIE, REFRESH_COOKIE = AUTH_COOKIE_NAMES

log = logging.getLogger("apiedge.security")

# What each access dependency demands, published per operation as ``x-apiedge-access`` in the
# OpenAPI document (see :func:`annotate_access`). Filled when the dependencies are created.
ACCESS: dict[Callable[..., object], dict[str, str]] = {}


def get_db(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


DB = Annotated[Session, Depends(get_db)]


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def unauthorized(code: str = "not_authenticated") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail=code, headers={"WWW-Authenticate": "Bearer"}
    )


def forbidden() -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, detail="permission_denied")


def not_found(what: str = "Not found") -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=what)


@dataclass
class Caller:
    """The authenticated user of this request, with its session."""

    user: User
    principal: Principal
    session: Session
    ip: str | None

    @property
    def id(self) -> int:
        return self.user.id

    @property
    def username(self) -> str:
        return self.user.username


@dataclass
class TenantCaller(Caller):
    """A caller acting inside one tenant (the session is bound to it)."""

    tenant: Tenant

    @property
    def tenant_id(self) -> int:
        return self.tenant.id


def _bearer_or_cookie(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return request.cookies.get(SESSION_COOKIE) or None


def _authenticate(request: Request, session: Session, *, allow_password_change: bool) -> Caller:
    token = _bearer_or_cookie(request)
    if not token:
        raise unauthorized()
    signer: TokenSigner = request.app.state.token_signer
    try:
        claims = signer.verify(token)
    except AuthError as exc:
        raise unauthorized("invalid_token") from exc
    user = session.get(User, claims.user_id)
    if user is None or not user.is_active or user.token_version != claims.token_version:
        raise unauthorized("invalid_token")
    if user.tenant_id is not None:
        tenant = session.get(Tenant, user.tenant_id)
        if tenant is None or not tenant.is_active:
            raise unauthorized("invalid_token")
    elif not user.is_superadmin:
        raise unauthorized("invalid_token")  # platform users must be SuperAdmins
    principal = load_principal(user)
    if principal.must_change_password and not allow_password_change:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="password_change_required")
    return Caller(user=user, principal=principal, session=session, ip=client_ip(request))


def authenticated(request: Request, session: DB) -> Caller:
    """Any signed-in user, also while a password change is pending."""
    return _authenticate(request, session, allow_password_change=True)


def active_caller(request: Request, session: DB) -> Caller:
    """A signed-in user with no pending password change."""
    return _authenticate(request, session, allow_password_change=False)


def _deny(caller: Caller, permission: str, tenant_id: int | None) -> HTTPException:
    log.warning(
        "access denied",
        extra={"user": caller.username, "permission": permission, "tenant_id": tenant_id},
    )
    return forbidden()


def require_platform(permission: str) -> Callable[..., Caller]:
    if permission not in PERMISSIONS:
        raise ValueError(f"unknown permission {permission!r}")

    def dep(caller: Annotated[Caller, Depends(active_caller)]) -> Caller:
        if not caller.principal.has(permission, None):
            raise _deny(caller, permission, None)
        return caller

    ACCESS[dep] = {"scope": "platform", "permission": permission}
    return dep


def require(permission: str, *, product_scoped: bool = False) -> Callable[..., TenantCaller]:
    """Tenant-scoped permission check for routes under ``/tenants/{tenant_id}``."""
    if permission not in PERMISSIONS:
        raise ValueError(f"unknown permission {permission!r}")

    def dep(
        tenant_id: Annotated[int, Path(ge=1)],
        caller: Annotated[Caller, Depends(active_caller)],
    ) -> TenantCaller:
        if not caller.principal.can_access_tenant(tenant_id):
            raise not_found("Tenant not found")
        tenant = caller.session.get(Tenant, tenant_id)
        if tenant is None:
            raise not_found("Tenant not found")
        allowed = (
            caller.principal.has_any(permission, tenant_id)
            if product_scoped
            else caller.principal.has(permission, tenant_id)
        )
        if not allowed:
            raise _deny(caller, permission, tenant_id)
        bind_tenant(caller.session, tenant_id)
        return TenantCaller(
            user=caller.user,
            principal=caller.principal,
            session=caller.session,
            ip=caller.ip,
            tenant=tenant,
        )

    ACCESS[dep] = {"scope": "product" if product_scoped else "tenant", "permission": permission}
    return dep


def require_any(permission: str) -> Callable[..., TenantCaller]:
    """Tenant access plus ``permission`` tenant-wide or for at least one product."""
    return require(permission, product_scoped=True)


def deny(caller: Caller, permission: str, tenant_id: int | None) -> HTTPException:
    """403 for a missing permission (logged without user-influenced values beyond the name)."""
    return _deny(caller, permission, tenant_id)


ACCESS[authenticated] = {"scope": "signed-in"}
ACCESS[active_caller] = {"scope": "signed-in"}
_PRECEDENCE = {"platform": 0, "tenant": 0, "product": 0, "signed-in": 1}


def _access_of(dependant: Any) -> dict[str, str] | None:
    """The strictest access requirement among a route's (nested) dependencies."""
    found: dict[str, str] | None = ACCESS.get(dependant.call) if dependant.call else None
    for sub in dependant.dependencies:
        candidate = _access_of(sub)
        if candidate and (
            found is None or _PRECEDENCE[candidate["scope"]] < _PRECEDENCE[found["scope"]]
        ):
            found = candidate
    return found


def annotate_access(routes: list[Any]) -> None:
    """Record each operation's access requirement as ``x-apiedge-access`` in OpenAPI.

    ``scope`` is ``public``, ``signed-in``, ``platform`` (SuperAdmins), ``tenant`` (the
    permission tenant-wide) or ``product`` (tenant-wide or for the product concerned).
    """
    for route in routes:
        if isinstance(route, APIRoute):
            access = _access_of(route.dependant) or {"scope": "public"}
            route.openapi_extra = {**(route.openapi_extra or {}), "x-apiedge-access": access}
