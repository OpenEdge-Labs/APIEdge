# Copyright 2026 Alingan Patra
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
