# ADR 0005: Products, owners and product-scoped access

- Status: accepted
- Date: 2026-11-01
- Task: T-005

## Context

Products are the second level of the domain model (Tenant > Product > API). T-003 already allows
role grants scoped to a product (`role_assignments.product_id`) but had no products table to
reference. Products need owners and a lifecycle.

## Decision

* New tables `products` (tenant-owned; name unique per tenant; `lifecycle` with a CHECK constraint)
  and `product_owners` (tenant-owned link to users of the same tenant). Migration 0003 adds them and
  the foreign key `role_assignments.product_id -> products.id ON DELETE CASCADE`. Product-scoped
  grants created before 0003 could not point at a real product and are deleted.
* Owners are informational contacts, not an access mechanism. Access comes only from role grants,
  so there is one authorization model to audit.
* Product routes use `require_any(permission)`: tenant access plus the permission tenant-wide or for
  at least one product; the handler then checks `Principal.has(permission, tenant, product)`.
  A product the caller cannot read answers 404; one they can read but not change answers 403.
* Lifecycle: draft -> published -> deprecated -> retired; deprecated may return to published, a
  draft may be retired directly, retired is final and read-only. Lifecycle changes use their own
  route and permission (`product:publish`). Only draft and retired products can be deleted.

## Consequences

* APIs (T-006) hang off `products` and reuse the same product-scoped checks.
* Deleting a product removes its scoped grants. Principals are rebuilt from the database on every
  request, so the change applies immediately.
