# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""RBAC catalog and permission evaluation (T-003, OWASP A01 / API1 / API5).

Permissions are ``resource:action`` strings. Roles bundle permissions. A role assignment grants a
role to a user in a tenant (``product_id`` NULL) or only for one product of that tenant.
SuperAdmins (``users.is_superadmin``) hold every permission in every tenant.

The catalog is code; migrations seed it into the ``permissions`` / ``roles`` tables, and
``tests/integration/test_rbac_catalog.py`` fails if the two drift apart.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

PERMISSIONS: dict[str, str] = {
    # Platform-level (only SuperAdmins; never grantable through tenant roles)
    "tenant:create": "Create tenants",
    "tenant:delete": "Delete tenants",
    "settings:update": "Change system settings",
    # Tenant administration
    "tenant:read": "View the tenant",
    "tenant:update": "Change the tenant's name and status",
    "user:read": "View users",
    "user:create": "Create users",
    "user:update": "Change, disable, unlock users and reset passwords",
    "user:delete": "Delete users",
    "role:read": "View roles and role assignments",
    "role:create": "Create custom roles",
    "role:update": "Change custom roles",
    "role:delete": "Delete custom roles",
    "role:assign": "Grant and revoke roles",
    "audit:read": "View the audit log",
    "settings:read": "View system settings",
    # Products and APIs (T-005, T-006)
    "product:read": "View products",
    "product:create": "Create products",
    "product:update": "Change products",
    "product:delete": "Delete products",
    "product:publish": "Change a product's lifecycle state",
    "api:read": "View APIs",
    "api:create": "Create APIs",
    "api:update": "Change APIs and routes",
    "api:delete": "Delete APIs",
    "api:publish": "Change an API's lifecycle state",
    "policy:read": "View policy chains",
    "policy:update": "Change policy chains",
    "script:update": "Write low-code script policies",
    "apikey:read": "View API keys",
    "apikey:manage": "Create and revoke API keys",
    # Debugging and analytics (T-012, T-013)
    "inspector:view": "View captured traffic (masked)",
    "inspector:capture": "Start and stop traffic capture",
    "inspector:unmask": "View captured traffic unmasked",
    "analytics:view": "View analytics",
    # Consumers (T-014)
    "plan:read": "View plans",
    "plan:update": "Create and change plans",
    "consumer:read": "View consumers and applications",
    "consumer:update": "Create and change consumers and applications",
    "subscription:read": "View subscriptions",
    "subscription:update": "Approve and change subscriptions",
}

PLATFORM_PERMISSIONS = frozenset({"tenant:create", "tenant:delete", "settings:update"})
TENANT_PERMISSIONS = frozenset(PERMISSIONS) - PLATFORM_PERMISSIONS

SUPERADMIN = "SuperAdmin"


def _all(*resources: str, actions: Iterable[str] | None = None) -> set[str]:
    acts = set(actions) if actions is not None else None
    return {
        p
        for p in TENANT_PERMISSIONS
        if p.split(":")[0] in resources and (acts is None or p.split(":")[1] in acts)
    }


_READ = {p for p in TENANT_PERMISSIONS if p.endswith(":read")}

BUILTIN_ROLES: dict[str, tuple[str, frozenset[str]]] = {
    SUPERADMIN: ("Full access to the platform and every tenant", frozenset(PERMISSIONS)),
    "TenantAdmin": ("Full access within a tenant", TENANT_PERMISSIONS),
    "ProductOwner": (
        "Owns products: APIs, policies, plans, subscriptions and debugging",
        frozenset(
            _all("product", actions=("read", "update", "publish"))
            | _all("api", "policy", "script", "plan", "subscription", "apikey")
            | {"consumer:read", "inspector:view", "inspector:capture", "analytics:view"}
        ),
    ),
    "APIDeveloper": (
        "Builds APIs and policies",
        frozenset(
            {"product:read", "api:read", "api:create", "api:update"}
            | _all("policy", "script", "apikey")
            | {"inspector:view", "inspector:capture", "analytics:view", "plan:read"}
        ),
    ),
    "Viewer": ("Read-only access", frozenset(_READ | {"analytics:view", "inspector:view"})),
    "Consumer": (
        "Discovers APIs and manages own subscriptions",
        frozenset({"product:read", "api:read", "plan:read", "subscription:read"}),
    ),
}


@dataclass(frozen=True)
class Grant:
    """Permissions a user holds from one assignment."""

    tenant_id: int
    product_id: int | None
    permissions: frozenset[str]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, as evaluated for one request."""

    user_id: int
    username: str
    tenant_id: int | None
    is_superadmin: bool
    must_change_password: bool = False
    grants: tuple[Grant, ...] = field(default_factory=tuple)

    def can_access_tenant(self, tenant_id: int) -> bool:
        return self.is_superadmin or self.tenant_id == tenant_id

    def has(self, permission: str, tenant_id: int | None, product_id: int | None = None) -> bool:
        """Deny by default. Platform permissions need a SuperAdmin."""
        if permission not in PERMISSIONS:
            return False
        if self.is_superadmin:
            return True
        if permission in PLATFORM_PERMISSIONS or tenant_id is None:
            return False
        if self.tenant_id != tenant_id:
            return False
        return any(
            permission in g.permissions
            and g.tenant_id == tenant_id
            and (g.product_id is None or g.product_id == product_id)
            for g in self.grants
        )

    def has_any(self, permission: str, tenant_id: int) -> bool:
        """True if ``permission`` is held tenant-wide or for at least one product."""
        if permission not in PERMISSIONS or permission in PLATFORM_PERMISSIONS:
            return self.is_superadmin and permission in PERMISSIONS
        if self.is_superadmin:
            return True
        if self.tenant_id != tenant_id:
            return False
        return any(permission in g.permissions and g.tenant_id == tenant_id for g in self.grants)

    def product_ids_with(self, permission: str, tenant_id: int) -> frozenset[int] | None:
        """Products where ``permission`` is held; ``None`` means every product (tenant-wide)."""
        if self.has(permission, tenant_id):
            return None
        if self.tenant_id != tenant_id:
            return frozenset()
        return frozenset(
            g.product_id
            for g in self.grants
            if g.product_id is not None and g.tenant_id == tenant_id and permission in g.permissions
        )

    def tenant_permissions(self, tenant_id: int) -> frozenset[str]:
        """Permissions held tenant-wide (product-scoped grants excluded)."""
        if self.is_superadmin:
            return frozenset(PERMISSIONS)
        if self.tenant_id != tenant_id:
            return frozenset()
        out: set[str] = set()
        for g in self.grants:
            if g.tenant_id == tenant_id and g.product_id is None:
                out |= g.permissions
        return frozenset(out)
