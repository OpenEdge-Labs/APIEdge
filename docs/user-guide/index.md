<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# User Guide

This guide is for the people who build, publish and debug APIs in the APIEdge console. It covers
the **no-code** tools available today (forms for products, APIs, routes and policies) and the
status of the **low-code** tools. Administrators should also read the
[Administrator Guide](../admin-guide/index.md).

| Page | Covers |
|---|---|
| [Products](products.md) | Bundling APIs into products, owners, lifecycle |
| [APIs](apis.md) | Base path, version, upstreams, routes, lifecycle, the API form editor |
| [Policies](policies.md) | API keys, JWT, rate limits, transforms, CORS, IP filters, caching, mocks |
| [Calling APIs through the gateway](gateway.md) | Gateway URLs, routing, load balancing, errors, hot reload |
| [Low-code](low-code.md) | What exists today and what is upcoming (script policies, flow builder) |
| [Packet Inspector Guide](inspector.md) | Capturing and replaying traffic, policy traces, HAR export |
| [Analytics Guide](analytics.md) | Traffic, latency and error dashboards, CSV export, Prometheus |

## Concepts

```
Tenant (organization)          isolation boundary; its slug is the first path segment on the gateway
 └── Product                   a bundle of APIs with owners and a lifecycle
      └── API                  base path, version, upstreams, lifecycle
           ├── Route           methods + path relative to the base path
           └── Policy chain    ordered policies, each for all routes or selected ones
```

Products and APIs move through the same lifecycle: `draft -> published -> deprecated -> retired`.
The gateway serves only published and deprecated APIs in non-retired products.

What you can see and change depends on your roles. Buttons for actions you may not perform are
hidden, and the server checks every action again. Roles can be granted for the whole tenant or
for a single product.

## Tutorial: publish your first API

This walk-through needs a user with the `TenantAdmin` role in a tenant (or a SuperAdmin working in
a tenant). It publishes a public echo service as tenant `acme`. Replace the upstream with one of
your own services; private or internal addresses must first be allowed by an administrator (see
the SSRF settings in [configuration](../admin-guide/configuration.md)).

1. **Create a product.** Open **Products**, fill in **New product** with the name `Orders` and
   click create. It starts as a draft.
2. **Create an API.** Click **APIs** on the product, then add an API:
    * name `Orders API`, version `v1`, base path `/orders`;
    * under **Upstreams**, one row with the URL of your backend, for example
      `https://httpbin.org/anything`, weight `1`;
    * under **Routes**, one row with method `GET` and path `/{id}`, and another with `POST` and
      path `/`.

    Save. The form checks paths, methods and overlapping routes; the server checks again,
    including the SSRF guard for the upstream URL.
3. **Add policies (optional).** Click **Policies** on the API and add, for example, an
   **API key** policy and a **Rate limit** of 10 requests per minute per consumer. Save. Then
   create a key in the product's **API keys** panel and copy it: it is shown only once. See
   [Policies](policies.md).
4. **Publish.** Click **Publish** on the API and on the product. Publishing an API needs at
   least one upstream and one route.
5. **Call it.** The API list shows its **Gateway** path. With the default gateway address:

    ```
    curl -H "X-API-Key: <your key>" http://127.0.0.1:8081/acme/orders/42
    ```

    Without the API key policy, leave out the header. A wrong path answers 404, a wrong method
    405; see [errors](gateway.md#errors).
6. **Watch it.** Open **Analytics** to see requests, latency and status codes (data appears
   within about `APIEDGE_ANALYTICS_FLUSH_INTERVAL_SECONDS`, 10 seconds by default), or start a
   capture in **Packet inspector** to see each request with its policy-by-policy trace.

Changes to a published API reach the gateway within moments, without a restart. To take an API
out of service, **Deprecate** it (still served, with a `Deprecation: true` header) and later
**Retire** it (the gateway answers 410).

## Automating the same steps

Everything the console does goes through the admin API, so the tutorial can be scripted. See the
[Admin API guide](../api/index.md) for signing in from a script and the
[reference](../api/reference.md) for each operation and the permission it needs.
