# Policies

Policies add security and traffic rules to an API without code: API keys, JWT validation, rate
limits and quotas, header and body transforms, CORS, IP allow/deny lists, response caching and
mock responses. Each API has an ordered **policy chain**.

Open **Products**, choose a product's **APIs**, then **Policies** on an API. You need
`policy:read` to see a chain and `policy:update` to change it (TenantAdmin, ProductOwner and
APIDeveloper have both; Viewer can read). Changes reach the gateway within moments, without a
restart. Retired APIs are read-only.

## How the chain runs

* Policies run **top to bottom** on each request. A policy can reject the request (401, 403,
  429), answer it itself (mock, cache hit) or change it (transform). Once a policy answers, the
  remaining policies and the upstream are skipped.
* The response then passes back through the policies that ran, **bottom to top**. That is how
  CORS headers, rate-limit headers and response transforms also reach answers produced inside
  the chain (for example a 401 from the API key policy).
* **Routes**: tick routes to limit a policy to them; with no route ticked it applies to every
  route of the API. If a route is later removed from the API, its tick stops matching
  (the editor marks it).
* **Enabled**: untick to keep a policy configured but switched off.
* Every decision is recorded in a per-request trace (policy, outcome, detail, duration) that the
  packet inspector will show (T-012). Traces never contain credentials.
* If a stored policy cannot be used (for example its secret can no longer be decrypted after the
  master key was replaced), the API answers **503** instead of skipping the policy.

A typical order: **CORS**, **IP filter**, **API key** or **JWT**, **rate limit**, **cache**,
**transform**, then the upstream (or a **mock**).

## API key

Requires a valid API key of the API's product.

| Setting | Default | Meaning |
|---|---|---|
| Header | `x-api-key` | Request header that carries the key |
| Query parameter | off | Also accept the key in this query parameter (discouraged: URLs end up in logs) |
| Do not forward the key | on | Remove the key before the request goes upstream |

Manage keys with **API keys** on the product's API list (`apikey:read` to view,
`apikey:manage` to create and revoke). A key looks like `ak_...` and is **shown once** when it is
created; APIEdge stores only its SHA-256 hash and the first characters (the prefix) to recognise
it. Keys can have an expiry date and can be revoked; revoked keys stop working immediately.
A key works for every API of its product that has an API key policy, and for no other product
or tenant.

Answers: 401 with `WWW-Authenticate: APIKey` for a missing, unknown, revoked or expired key.
Analytics shows the caller as consumer `key:<key name>`.

> Keys are attached to products for now. Consumers, applications and plans (T-014) will own them.

## JWT validation

Requires a signed JSON Web Token, by default as `Authorization: Bearer <token>`.

| Setting | Meaning |
|---|---|
| Allowed algorithms | The only accepted `alg` values. Use HS256/384/512 (shared secret) **or** RS*, PS*, ES* (public key or JWKS), never both; `none` is never accepted |
| Shared secret | For HS*: at least 32 bytes. Stored encrypted and never shown again; leave the field empty to keep the stored secret |
| Public key | For RS*/PS*/ES*: a PEM public key (RSA keys need at least 2048 bits) |
| JWKS URL | For RS*/PS*/ES*: an `https` URL of the issuer's key set. It must pass the [SSRF guard](../SECURITY.md) and is fetched through it; keys are cached (default 300 s) and refreshed when a token names an unknown `kid` (at most every 30 s) |
| Issuer, audiences | When set, `iss` must match and `aud` must contain one of the audiences |
| Require an expiry | On by default: tokens without `exp` are refused |
| Clock leeway | Tolerance for `exp` and `nbf`, 0-300 s (default 30) |
| Header | Header carrying the token (`authorization` expects the `Bearer` scheme; any other header carries the raw token) |
| Consumer claim | Claim that names the caller in analytics (default `sub`, shown as `jwt:<value>`) |
| Do not forward the token | Remove the token before the request goes upstream (off by default) |

Answers: 401 with `WWW-Authenticate: Bearer` for a missing or invalid token, 503 when the JWKS
cannot be fetched and no keys are cached.

## Rate limit / quota

| Setting | Default | Meaning |
|---|---|---|
| Requests per window | (required) | The limit |
| Window | 60 s | Up to 30 days: use 86400 for a daily quota |
| Count per | consumer | `consumer` (the API key or JWT identity, else the client address), `ip` (client address) or `api` (all callers together) |

Answers carry `RateLimit-Policy`, `RateLimit-Limit`, `RateLimit-Remaining` and
`RateLimit-Reset` headers. Beyond the limit the gateway answers **429** with `Retry-After`
(seconds until the window resets). Windows are fixed (they reset at multiples of the window
length).

With `APIEDGE_REDIS_URL` set, all gateway processes share the counters; otherwise each process
counts on its own (see the [configuration](../admin-guide/configuration.md)). Put the rate limit
after the authentication policy so it can count per consumer.

## Header / body transform

Changes the request before it goes upstream and the response before it goes back.

* **Set / remove headers**: one per line, `name: value`. Values may use the placeholders
  `{consumer}`, `{request_id}` and `{client_ip}` (request headers only), for example
  `x-consumer: {consumer}`.
* **Set / remove query parameters** (request only): `name=value`, one per line.
* **Set / remove JSON fields**: dot paths into a JSON object body, for example
  `meta.source = "gateway"` (the value is JSON) or `password` to remove. Bodies that are not a
  JSON object are left unchanged; response bodies larger than the configured limit (default
  1 MiB) or compressed by the upstream are left unchanged too.

Headers the gateway manages (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection` and
other hop-by-hop headers, `X-Forwarded-*`, `X-Request-ID`, response `Content-Encoding`) cannot
be changed. Header values cannot contain line breaks.

## CORS

Lets browser applications on other origins call the API.

* **Allowed origins**: `scheme://host[:port]`, one per line, or `*` for any origin (not
  together with credentials).
* **Allowed methods**, **allowed request headers** (`*` allows any), **exposed response
  headers**, **allow credentials**, **preflight cache** (`Access-Control-Max-Age`).

Browser preflights (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) are answered by
the CORS policy of the route they ask about, before any other policy runs and even if the route
does not list `OPTIONS`. A preflight for an origin, method or header that is not allowed gets
**403** without CORS headers. Normal requests from allowed origins get
`Access-Control-Allow-Origin` (and `Vary: Origin`); other origins get no CORS headers, so
browsers block them while server-to-server calls keep working. Put CORS **first** so that
rejections by later policies also carry CORS headers.

## IP allow / deny

Addresses or CIDR ranges (IPv4 and IPv6), one per line. A **denied** address is always refused;
with an **allow** list, only listed addresses get through. Refused requests get **403**.

The client address is the address of the connection. If the gateway runs behind load balancers
or reverse proxies, an administrator lists them in `APIEDGE_GATEWAY_TRUSTED_PROXIES`; only then is
`X-Forwarded-For` used (read from the right, skipping trusted proxies), so callers cannot forge
their address.

## Response cache

Serves repeated GET and HEAD requests from memory.

| Setting | Default | Meaning |
|---|---|---|
| Time to live | 60 s | Upper bound; an upstream `max-age` / `s-maxage` can only shorten it |
| Largest cached response | 1 MiB | Larger answers are not stored |
| Also vary on | - | Extra request headers that are part of the cache key (`Accept` and `Accept-Encoding` always are) |
| Cache answers to authenticated requests | off | See below |

Not cached: other methods; statuses other than 200, 203, 204, 300, 301, 404, 405, 410;
responses with `Cache-Control: no-store`, `no-cache` or `private`, with `Set-Cookie`, or with a
`Vary` on headers that are not in the key. A request with `Cache-Control: no-cache` (or
`Pragma: no-cache`) fetches a fresh answer; `no-store` bypasses the cache.

Requests with credentials (an API key or JWT identity, an `Authorization` or a `Cookie` header)
bypass the cache unless **cache answers to authenticated requests** is on; then each caller has
separate entries. Answers show `X-Cache: HIT` (with `Age`) or `X-Cache: MISS`. The cache lives in
each gateway process (size: `APIEDGE_GATEWAY_CACHE_MAX_BYTES`, default 64 MiB).

## Mock response

Answers every request it applies to with a fixed status (200-599), content type, headers and
body (up to 64 KiB); the upstream is not called. Useful while the backend does not exist yet,
or limited to some routes.

## Admin API

```
GET  /api/v1/tenants/{tenant}/products/{product}/apis/{api}/policies       policy:read
PUT  /api/v1/tenants/{tenant}/products/{product}/apis/{api}/policies       policy:update
GET  /api/v1/tenants/{tenant}/products/{product}/api-keys                  apikey:read
POST /api/v1/tenants/{tenant}/products/{product}/api-keys                  apikey:manage
POST /api/v1/tenants/{tenant}/products/{product}/api-keys/{key}/revoke     apikey:manage
```

`PUT .../policies` replaces the chain:

```json
{
  "policies": [
    {"type": "cors", "config": {"allow_origins": ["https://app.example.com"]}},
    {"type": "api-key"},
    {"type": "rate-limit", "config": {"limit": 100, "window_seconds": 60}},
    {"type": "mock", "routes": ["/health"], "config": {"status": 200, "body": "{\"ok\":true}"}}
  ]
}
```

The response lists the policies with their ids (keep them when sending the chain back) and
`secrets_set` (which stored secrets exist; their values are never returned; send `null` to keep
them). Changes are recorded in the audit log (`api.policies.update`, `apikey.create`,
`apikey.revoke`).
