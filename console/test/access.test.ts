// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { can, canAnyProduct, canProduct, grantable, navFor, pageFromHash } from "../src/access";
import type { Me } from "../src/types";

function me(overrides: Partial<Me> = {}): Me {
  return {
    id: 1,
    username: "u",
    email: null,
    tenant_id: 7,
    is_superadmin: false,
    must_change_password: false,
    mfa_enabled: false,
    permissions: [],
    product_permissions: [],
    ...overrides,
  };
}

test("a user without permissions only sees their account", () => {
  assert.deepEqual(navFor(me()).map((n) => n.page), ["account"]);
});

test("a Viewer sees read screens but not system settings", () => {
  const viewer = me({ permissions: ["tenant:read", "user:read", "role:read", "audit:read", "settings:read"] });
  assert.deepEqual(navFor(viewer).map((n) => n.page), ["tenants", "users", "roles", "audit", "account"]);
});

test("an APIDeveloper sees products but not users, roles or audit", () => {
  const dev = me({ permissions: ["product:read", "api:create", "api:read"] });
  assert.deepEqual(navFor(dev).map((n) => n.page), ["products", "account"]);
});

test("a SuperAdmin sees everything, including system settings", () => {
  const root = me({ is_superadmin: true, tenant_id: null });
  assert.deepEqual(navFor(root).map((n) => n.page), ["tenants", "products", "analytics", "inspector", "tls", "oauth", "ldap", "users", "roles", "audit", "settings", "account"]);
  assert.ok(can(root, "tenant:create"));
});

test("can() is deny by default", () => {
  assert.equal(can(me({ permissions: ["user:read"] }), "user:create"), false);
  assert.equal(can(me({ permissions: ["user:read"] }), "user:read"), true);
});

test("the hash cannot open a page the user may not see", () => {
  const viewer = me({ permissions: ["user:read"] });
  assert.equal(pageFromHash("#/users", viewer), "users");
  assert.equal(pageFromHash("#/settings", viewer), "users");
  assert.equal(pageFromHash("#/roles", viewer), "users");
  assert.equal(pageFromHash("", viewer), "users");
  assert.equal(pageFromHash("#/nonsense", me()), "account");
});

test("grantable() offers only permissions the user holds", () => {
  const limited = me({ permissions: ["user:read", "role:create"] });
  assert.deepEqual([...grantable(limited, ["user:read", "user:delete", "role:create"])], ["user:read", "role:create"]);
});

test("a product-scoped grant shows Products and only allows that product", () => {
  const owner = me({ product_permissions: [{ product_id: 3, permissions: ["product:read", "product:update"] }] });
  assert.deepEqual(navFor(owner).map((n) => n.page), ["products", "account"]);
  assert.equal(canProduct(owner, "product:update", 3), true);
  assert.equal(canProduct(owner, "product:update", 4), false);
  assert.equal(canProduct(owner, "product:delete", 3), false);
  assert.equal(canAnyProduct(owner, "product:create"), false);
  assert.equal(can(owner, "product:read"), false);
});

test("tenant-wide product permissions apply to every product", () => {
  const admin = me({ permissions: ["product:read", "product:delete"] });
  assert.equal(canProduct(admin, "product:delete", 99), true);
  assert.equal(canAnyProduct(admin, "product:read"), true);
});

test("the packet inspector needs inspector:view, tenant-wide or for a product", () => {
  assert.equal(navFor(me({ permissions: ["analytics:view"] })).some((n) => n.page === "inspector"), false);
  assert.ok(navFor(me({ permissions: ["inspector:view"] })).some((n) => n.page === "inspector"));
  const scoped = me({ product_permissions: [{ product_id: 4, permissions: ["inspector:view"] }] });
  assert.ok(navFor(scoped).some((n) => n.page === "inspector"));
});

test("the TLS page needs tls:read", () => {
  assert.ok(navFor(me({ permissions: ["tls:read"] })).some((n) => n.page === "tls"));
  assert.ok(!navFor(me({ permissions: ["product:read"] })).some((n) => n.page === "tls"));
  assert.ok(navFor(me({ permissions: ["oauth:read"] })).some((n) => n.page === "oauth"));
  assert.ok(!navFor(me({ permissions: ["tls:read"] })).some((n) => n.page === "oauth"));
});
