# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from apiedge.security.rbac import (
    BUILTIN_ROLES,
    PERMISSIONS,
    PLATFORM_PERMISSIONS,
    Grant,
    Principal,
)


def _p(*grants: Grant, superadmin: bool = False, tenant: int | None = 1) -> Principal:
    return Principal(1, "u", tenant, superadmin, grants=grants)


def test_permissions_are_resource_action() -> None:
    for name in PERMISSIONS:
        resource, _, action = name.partition(":")
        assert resource and action and name == name.lower()


def test_builtin_roles_use_known_permissions_and_only_superadmin_is_platform() -> None:
    for name, (_, perms) in BUILTIN_ROLES.items():
        assert perms <= set(PERMISSIONS)
        assert bool(perms & PLATFORM_PERMISSIONS) == (name == "SuperAdmin")


def test_deny_by_default() -> None:
    p = _p()
    assert not p.has("user:read", 1)
    assert not p.has("no:such", 1)


def test_tenant_grant() -> None:
    p = _p(Grant(1, None, frozenset({"user:read"})))
    assert p.has("user:read", 1)
    assert p.has("user:read", 1, product_id=7)  # tenant-wide covers every product
    assert not p.has("user:read", 2)  # other tenant
    assert not p.has("user:create", 1)
    assert not p.has("user:read", None)  # platform scope


def test_product_scoped_grant() -> None:
    p = _p(Grant(1, 7, frozenset({"api:update"})))
    assert p.has("api:update", 1, product_id=7)
    assert not p.has("api:update", 1, product_id=8)
    assert not p.has("api:update", 1)  # not tenant-wide
    assert p.tenant_permissions(1) == frozenset()


def test_grant_in_foreign_tenant_is_ignored() -> None:
    # Defence in depth: a grant whose tenant differs from the user's tenant never applies.
    p = _p(Grant(2, None, frozenset({"user:read"})), tenant=1)
    assert not p.has("user:read", 2)
    assert p.tenant_permissions(2) == frozenset()


@pytest.mark.parametrize("perm", sorted(PLATFORM_PERMISSIONS))
def test_platform_permissions_need_superadmin(perm: str) -> None:
    assert not _p(Grant(1, None, frozenset(PERMISSIONS))).has(perm, 1)
    assert _p(superadmin=True, tenant=None).has(perm, None)


def test_superadmin_everywhere() -> None:
    sa = _p(superadmin=True, tenant=None)
    assert sa.has("user:delete", 99) and sa.can_access_tenant(99)
    assert sa.tenant_permissions(5) == frozenset(PERMISSIONS)


def test_has_any_and_product_ids_with() -> None:
    scoped = Principal(
        user_id=1,
        username="p",
        tenant_id=7,
        is_superadmin=False,
        grants=(
            Grant(tenant_id=7, product_id=3, permissions=frozenset({"product:read"})),
            Grant(tenant_id=7, product_id=4, permissions=frozenset({"product:update"})),
        ),
    )
    assert scoped.has_any("product:read", 7)
    assert not scoped.has_any("product:read", 8)  # other tenant
    assert not scoped.has_any("product:delete", 7)
    assert not scoped.has_any("tenant:create", 7)  # platform permission
    assert not scoped.has_any("nope:nope", 7)
    assert scoped.product_ids_with("product:read", 7) == frozenset({3})
    assert scoped.product_ids_with("product:read", 8) == frozenset()
    wide = Principal(
        user_id=2,
        username="w",
        tenant_id=7,
        is_superadmin=False,
        grants=(Grant(tenant_id=7, product_id=None, permissions=frozenset({"product:read"})),),
    )
    assert wide.product_ids_with("product:read", 7) is None
    root = Principal(user_id=3, username="r", tenant_id=None, is_superadmin=True)
    assert root.has_any("tenant:create", 7) and root.product_ids_with("product:read", 7) is None
