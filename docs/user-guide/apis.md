# APIs

An **API** lives inside a [product](products.md). It has a base path where the gateway will expose
it (T-007), one or more **upstreams** (the backend servers the gateway forwards to) and **routes**
(the operations it accepts). APIs are invisible to other tenants.

| Field | Rules |
|---|---|
| Name | 1-200 characters. Name and version are unique within the product |
| Version | Letters, digits and `. _ -`, up to 32 characters (default `v1`) |
| Base path | Starts with `/`, segments of letters, digits and `- _ . ~` (for example `/orders/v1`). Unique within the tenant. `/api/v1`, `/healthz`, `/readyz`, `/docs`, `/redoc`, `/openapi.json` and `/assets` are reserved. It can only change while the API is a draft |
| Description | Up to 2000 characters |
| Timeout | Upstream timeout in milliseconds, 100 to 300000 (default 30000) |
| Upstreams | Up to 20. Each has an `http` or `https` URL and a weight from 1 to 100 (traffic is shared by weight) |
| Routes | Up to 200. Each has one or more HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS), a path relative to the base path and a description |
| Lifecycle | `draft` (new APIs), `published`, `deprecated`, `retired` |

**Route paths** start with `/`. Use `{name}` for a path parameter (`/orders/{id}`) and end with
`/*` to match everything below a path (`/files/*`, or `/*` for the whole API). Two routes may not
accept the same method on the same path (`/a/{id}` and `/a/{x}` count as the same path).

**Upstream URLs are checked by the SSRF guard** when you save: credentials in the URL, schemes
other than http/https, and hosts that resolve to private, loopback, link-local, carrier-grade NAT
or cloud metadata addresses are refused. For on-premise backends an administrator can allow
specific networks (`APIEDGE_SSRF_ALLOW_CIDRS`) or private addresses in general
(`APIEDGE_SSRF_ALLOW_PRIVATE`); cloud metadata addresses stay blocked unless a CIDR allows them
explicitly. See the [configuration guide](../admin-guide/configuration.md).

## Lifecycle

The same states as products: `draft -> published -> deprecated -> retired`, a deprecated API can
be published again, a draft can be retired directly, and retired is final.

* Publishing needs at least one upstream and one route. A published API keeps its base path and
  cannot remove all of its upstreams or routes.
* Retired APIs are read-only. Only draft and retired APIs can be deleted.
* In a retired product, APIs are read-only but can still be deprecated and retired.
* A product cannot be deleted while it still contains APIs.

## In the console (no-code form editor)

Open **Products** and click **APIs** on a product. The panel lists the product's APIs with their
base path, lifecycle and the number of upstreams and routes. Use **Edit** (or **View** when you
may not change it) to open the form editor:

1. Fill in name, version, base path, timeout and description.
2. Under **Upstreams**, add one row per backend URL and set its weight.
3. Under **Routes**, add one row per operation: tick the methods and enter the path.
4. Click **Create API** or **Save**. The form checks paths, methods, weights and overlapping routes
   before sending; the server checks everything again, including the SSRF guard.

Lifecycle buttons (Publish, Deprecate, Retire) and Delete appear only when you may use them.

## Permissions

A permission counts when it is held tenant-wide or through a role grant scoped to the product.

| Action | Permission | Built-in roles |
|---|---|---|
| List and view APIs | `api:read` | all roles |
| Create APIs | `api:create` | TenantAdmin, ProductOwner, APIDeveloper |
| Change APIs, upstreams and routes | `api:update` | TenantAdmin, ProductOwner, APIDeveloper |
| Publish, deprecate, retire | `api:publish` | TenantAdmin, ProductOwner |
| Delete | `api:delete` | TenantAdmin, ProductOwner |

## Admin API

All routes are under `/api/v1/tenants/{tenant_id}/products/{product_id}`.

| Route | Permission |
|---|---|
| `GET /apis` | `api:read` |
| `POST /apis` `{"name", "base_path", "version"?, "description"?, "timeout_ms"?, "upstreams"?, "routes"?}` | `api:create` |
| `GET /apis/{api_id}` | `api:read` |
| `PATCH /apis/{api_id}` (any of the fields above; `upstreams` and `routes` replace the lists) | `api:update` |
| `POST /apis/{api_id}/lifecycle` `{"lifecycle"}` | `api:publish` |
| `DELETE /apis/{api_id}` | `api:delete` |

`upstreams` is a list of `{"url", "weight"?}` and `routes` a list of
`{"methods": [...], "path", "description"?}`. Example:

```json
{
  "name": "Orders",
  "version": "v1",
  "base_path": "/orders",
  "upstreams": [{"url": "https://orders.internal.example.com", "weight": 1}],
  "routes": [
    {"methods": ["GET"], "path": "/"},
    {"methods": ["GET", "PUT"], "path": "/{id}"}
  ]
}
```

Responses: 404 for a product or API of another tenant, a product whose APIs you cannot read, or an
API that is not in the product of the path; 403 when you can read but may not perform the action;
400 when an upstream URL is refused by the SSRF guard; 422 for invalid fields (paths, methods,
overlapping routes, unknown fields); 409 for a base path already used in the tenant, a duplicate
name and version, a disallowed lifecycle move, publishing without upstreams or routes, or changing
a retired API. Every change is written to the audit log (`api.create`, `api.update`,
`api.lifecycle`, `api.delete`; the update event lists the changed fields).
