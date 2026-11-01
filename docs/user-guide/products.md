# Products

A **product** bundles the APIs a team offers ([APIs](apis.md); plans arrive with T-014). Each
product belongs to one tenant and is invisible to every other tenant.

| Field | Rules |
|---|---|
| Name | 1-200 characters, unique within the tenant |
| Description | Up to 2000 characters |
| Owners | Up to 20 usernames of the same tenant. They are the product's contacts; owning a product does **not** grant access (use a role grant, see below). When you create a product without naming owners, you become its owner (SuperAdmins outside the tenant do not). |
| Lifecycle | `draft` (new products), `published`, `deprecated`, `retired` |

## Lifecycle

```
draft --> published --> deprecated --> retired
  |           ^              |
  |           +--------------+   (a deprecated product can be published again)
  +--------------------------------> retired
```

* Retired is final: a retired product cannot be edited or moved again.
* Only draft and retired products that contain no APIs can be deleted (delete or retire and delete
  the APIs first). Deleting a product also revokes every role grant scoped to it.
* The APIs of a retired product are read-only, but can still be deprecated and retired.
* From T-007 the gateway enforces the lifecycle of APIs inside products.

## In the console

Open **Products** (shown when you can read at least one product). Pick a lifecycle filter, edit a
product (name, description, owners), move it through the lifecycle with the Publish / Deprecate /
Retire buttons, or delete it. The **New product** form is shown only to users who may create
products in the whole tenant. Buttons appear only for what you may do; the server checks every
action again.

To give someone access to a single product, open **Users**, choose the user, pick a role and set
**Scope** to "Only product ...". For example, the built-in `ProductOwner` role scoped to one product
lets that user edit, publish and deprecate that product only, and nothing else in the tenant.

## Admin API

All routes are under `/api/v1/tenants/{tenant_id}`. A permission counts if it is held tenant-wide
or through a grant scoped to the product.

| Route | Permission |
|---|---|
| `GET /products?lifecycle=` | `product:read` (lists only the products it covers) |
| `POST /products` `{"name", "description"?, "owners"?}` | `product:create` (tenant-wide) |
| `GET /products/{pid}` | `product:read` |
| `PATCH /products/{pid}` `{"name"?, "description"?, "owners"?}` | `product:update` |
| `POST /products/{pid}/lifecycle` `{"lifecycle"}` | `product:publish` |
| `DELETE /products/{pid}` | `product:delete` |

Responses: 404 for a product of another tenant or one you cannot read; 403 when you can read it but
may not perform the action (or hold the permission for no product at all); 409 for a duplicate
name, a disallowed lifecycle move, editing a retired product, deleting a published or deprecated
one, or deleting one that still contains APIs; 400 for unknown owners. Every change is written to the audit log (`product.create`,
`product.update`, `product.lifecycle`, `product.delete`).
