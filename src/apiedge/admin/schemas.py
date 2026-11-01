# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Admin API request/response models (T-003). Inputs are strict: unknown fields are rejected."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from apiedge.security.rbac import TENANT_PERMISSIONS

Username = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]{2,149}$")]
Email = Annotated[
    str, StringConstraints(max_length=320, pattern=r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{1,63}$")
]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
RoleName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,99}$")]
Secret = Annotated[str, StringConstraints(min_length=1, max_length=256)]
TotpCode = Annotated[str, StringConstraints(pattern=r"^\s*\d{6}\s*$")]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth


class LoginIn(In):
    username: Annotated[str, StringConstraints(min_length=1, max_length=150)]
    password: Secret
    totp_code: TotpCode | None = None


class ProductPermissions(Out):
    product_id: int
    permissions: list[str]


class MeOut(Out):
    id: int
    username: str
    email: str | None
    tenant_id: int | None
    is_superadmin: bool
    must_change_password: bool
    mfa_enabled: bool
    permissions: list[str] = Field(description="Permissions held tenant-wide (or platform-wide)")
    product_permissions: list[ProductPermissions] = Field(default_factory=list)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105  # nosec B105 - OAuth token type
    expires_in: int
    must_change_password: bool


class ChangePasswordIn(In):
    current_password: Secret
    new_password: Secret


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeIn(In):
    code: TotpCode


class MfaDisableIn(In):
    password: Secret
    code: TotpCode


# --- tenants


class TenantIn(In):
    slug: Slug
    name: Name


class TenantPatch(In):
    name: Name | None = None
    is_active: bool | None = None


class TenantOut(Out):
    id: int
    slug: str
    name: str
    is_active: bool
    created_at: datetime


# --- users


class UserCreate(In):
    username: Username
    email: Email | None = None
    password: Secret
    must_change_password: bool = True
    role_ids: list[int] = Field(default_factory=list, max_length=20)


class UserPatch(In):
    email: Email | None = None
    is_active: bool | None = None
    unlock: bool = False
    reset_mfa: bool = False


class ResetPasswordIn(In):
    new_password: Secret


class UserOut(Out):
    id: int
    tenant_id: int | None
    username: str
    email: str | None
    is_active: bool
    is_locked: bool = False
    mfa_enabled: bool
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None


# --- roles


class PermissionOut(BaseModel):
    name: str
    description: str
    platform_only: bool


def _check_permissions(v: list[str] | None) -> list[str] | None:
    if v is None:
        return v
    unknown = sorted(set(v) - TENANT_PERMISSIONS)
    if unknown:
        raise ValueError(f"unknown or platform-only permissions: {', '.join(unknown)}")
    return sorted(set(v))


class RoleIn(In):
    name: RoleName
    description: Annotated[str, StringConstraints(max_length=500)] = ""
    permissions: list[str] = Field(max_length=100)

    _perms = field_validator("permissions")(_check_permissions)


class RolePatch(In):
    name: RoleName | None = None
    description: Annotated[str, StringConstraints(max_length=500)] | None = None
    permissions: list[str] | None = Field(default=None, max_length=100)

    _perms = field_validator("permissions")(_check_permissions)


class RoleOut(Out):
    id: int
    tenant_id: int | None
    name: str
    description: str
    is_builtin: bool
    permissions: list[str]


class AssignmentIn(In):
    role_id: int = Field(ge=1)
    product_id: int | None = Field(default=None, ge=1)


class AssignmentOut(Out):
    id: int
    tenant_id: int
    user_id: int
    role_id: int
    role_name: str
    product_id: int | None
    created_at: datetime


# --- products (T-005)

ProductLifecycle = Literal["draft", "published", "deprecated", "retired"]
Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)]


def _unique_owners(v: list[str] | None) -> list[str] | None:
    return None if v is None else sorted(set(v))


class ProductIn(In):
    name: Name
    description: Description = ""
    owners: list[Username] | None = Field(
        default=None,
        max_length=20,
        description="Usernames in the tenant. Omitted: the caller, if they belong to the tenant.",
    )

    _owners = field_validator("owners")(_unique_owners)


class ProductPatch(In):
    name: Name | None = None
    description: Description | None = None
    owners: list[Username] | None = Field(default=None, max_length=20)

    _owners = field_validator("owners")(_unique_owners)


class LifecycleIn(In):
    lifecycle: ProductLifecycle


class OwnerOut(Out):
    user_id: int
    username: str


class ProductOut(Out):
    id: int
    tenant_id: int
    name: str
    description: str
    lifecycle: ProductLifecycle
    owners: list[OwnerOut]
    created_at: datetime
    updated_at: datetime


# --- APIs (T-006)

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
HTTP_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
Version = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")]
_SEGMENT = r"[A-Za-z0-9_.~-]+"
_PARAM = r"\{[A-Za-z_][A-Za-z0-9_]{0,63}\}"
BasePath = Annotated[str, StringConstraints(max_length=255, pattern=rf"^(/{_SEGMENT})+$")]
RoutePath = Annotated[
    str,
    StringConstraints(
        max_length=500, pattern=rf"^/(\*|({_SEGMENT}|{_PARAM})(/({_SEGMENT}|{_PARAM}))*(/\*)?)?$"
    ),
]
# Paths the APIEdge server answers itself; an API may not shadow them.
RESERVED_PREFIXES: tuple[str, ...] = (
    "/api/v1",
    "/healthz",
    "/readyz",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/assets",
)


def _no_dot_segments(path: str) -> None:
    if any(seg in (".", "..") for seg in path.split("/")):
        raise ValueError("'.' and '..' segments are not allowed")


def _check_base_path(v: str | None) -> str | None:
    if v is None:
        return None
    _no_dot_segments(v)
    low = v.lower()
    for prefix in RESERVED_PREFIXES:
        if low == prefix or low.startswith(prefix + "/"):
            raise ValueError(f"base path overlaps the reserved path {prefix}")
    return v


def route_key(path: str) -> str:
    """The path with parameter names erased: ``/a/{id}`` and ``/a/{x}`` match the same requests."""
    return "/".join("{}" if s.startswith("{") else s for s in path.split("/"))


class UpstreamIn(In):
    url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
    weight: int = Field(default=1, ge=1, le=100)


class RouteIn(In):
    methods: list[HttpMethod] = Field(min_length=1, max_length=len(HTTP_METHODS))
    path: RoutePath
    description: Description = ""

    @field_validator("methods")
    @classmethod
    def _methods(cls, v: list[str]) -> list[str]:
        return [m for m in HTTP_METHODS if m in set(v)]

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        _no_dot_segments(v)
        params = [s for s in v.split("/") if s.startswith("{")]
        if len(params) != len(set(params)):
            raise ValueError("path parameter names must be unique")
        return v


def _check_routes(v: list[RouteIn] | None) -> list[RouteIn] | None:
    if v is None:
        return None
    seen: dict[tuple[str, str], str] = {}
    for r in v:
        for m in r.methods:
            key = (m, route_key(r.path))
            if key in seen:
                raise ValueError(f"{m} {r.path} overlaps {m} {seen[key]}")
            seen[key] = r.path
    return v


class ApiIn(In):
    name: Name
    version: Version = "v1"
    base_path: BasePath
    description: Description = ""
    timeout_ms: int = Field(default=30000, ge=100, le=300000)
    upstreams: list[UpstreamIn] = Field(default_factory=list, max_length=20)
    routes: list[RouteIn] = Field(default_factory=list, max_length=200)

    _base = field_validator("base_path")(_check_base_path)
    _routes = field_validator("routes")(_check_routes)


class ApiPatch(In):
    name: Name | None = None
    version: Version | None = None
    base_path: BasePath | None = None
    description: Description | None = None
    timeout_ms: int | None = Field(default=None, ge=100, le=300000)
    upstreams: list[UpstreamIn] | None = Field(default=None, max_length=20)
    routes: list[RouteIn] | None = Field(default=None, max_length=200)

    _base = field_validator("base_path")(_check_base_path)
    _routes = field_validator("routes")(_check_routes)


class UpstreamOut(Out):
    url: str
    weight: int


class RouteOut(Out):
    methods: list[str]
    path: str
    description: str


class ApiOut(Out):
    id: int
    tenant_id: int
    product_id: int
    name: str
    version: str
    base_path: str
    # Where the gateway serves it: /<tenant slug><base path> on the gateway port (T-007).
    gateway_path: str
    description: str
    timeout_ms: int
    lifecycle: ProductLifecycle
    upstreams: list[UpstreamOut]
    routes: list[RouteOut]
    created_at: datetime
    updated_at: datetime


# --- audit


class AuditOut(Out):
    id: int
    tenant_id: int | None
    actor_user_id: int | None
    actor_username: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    client_ip: str | None
    request_id: str | None
    details: str | None
    created_at: datetime
