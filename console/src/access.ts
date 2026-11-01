// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// What the signed-in user may see and do. This only shapes the UI; the server enforces every
// permission on its own.
import type { Me } from "./types";

export type Page = "tenants" | "products" | "analytics" | "users" | "roles" | "audit" | "settings" | "account";

export interface NavItem {
  page: Page;
  label: string;
  /** Needs a selected tenant to be meaningful. */
  tenantScoped: boolean;
}

const NAV: (NavItem & { allowed: (me: Me) => boolean })[] = [
  {
    page: "tenants",
    label: "Tenants",
    tenantScoped: false,
    allowed: (me) => me.is_superadmin || can(me, "tenant:read"),
  },
  {
    page: "products",
    label: "Products",
    tenantScoped: true,
    allowed: (me) => canAnyProduct(me, "product:read"),
  },
  {
    page: "analytics",
    label: "Analytics",
    tenantScoped: true,
    allowed: (me) => canAnyProduct(me, "analytics:view"),
  },
  { page: "users", label: "Users", tenantScoped: true, allowed: (me) => can(me, "user:read") },
  { page: "roles", label: "Roles & permissions", tenantScoped: true, allowed: (me) => can(me, "role:read") },
  { page: "audit", label: "Audit log", tenantScoped: false, allowed: (me) => can(me, "audit:read") },
  { page: "settings", label: "System settings", tenantScoped: false, allowed: (me) => me.is_superadmin },
  { page: "account", label: "My account", tenantScoped: false, allowed: () => true },
];

/** True when the user holds `permission` tenant-wide (SuperAdmins hold everything). */
export function can(me: Me, permission: string): boolean {
  return me.is_superadmin || me.permissions.includes(permission);
}

/** True when `permission` is held tenant-wide or through a grant scoped to `productId`. */
export function canProduct(me: Me, permission: string, productId: number): boolean {
  return (
    can(me, permission) ||
    me.product_permissions.some((g) => g.product_id === productId && g.permissions.includes(permission))
  );
}

/** True when `permission` is held tenant-wide or for at least one product. */
export function canAnyProduct(me: Me, permission: string): boolean {
  return can(me, permission) || me.product_permissions.some((g) => g.permissions.includes(permission));
}

export function navFor(me: Me): NavItem[] {
  return NAV.filter((n) => n.allowed(me)).map(({ page, label, tenantScoped }) => ({ page, label, tenantScoped }));
}

const PAGES = new Set<string>(NAV.map((n) => n.page));

/** Reads the page from a location hash such as `#/users`; falls back to the first allowed page. */
export function pageFromHash(hash: string, me: Me): Page {
  const wanted = hash.replace(/^#\/?/, "").split(/[/?]/)[0];
  const allowed = navFor(me);
  const hit = allowed.find((n) => n.page === wanted);
  if (hit && PAGES.has(wanted)) return hit.page;
  return allowed[0]?.page ?? "account";
}

/** Permissions a user may put into a custom role or grant: only those they hold themselves. */
export function grantable(me: Me, all: string[]): Set<string> {
  return new Set(all.filter((p) => can(me, p)));
}
