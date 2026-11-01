# ADR 0009: Built-in policies and the policy pipeline

- Status: accepted
- Date: 2026-11-02
- Task: T-008

## Context

T-008 adds API key authentication, JWT validation, rate limits and quotas, header and body
transforms, CORS, IP allow/deny lists, response caching and mock responses, each configurable in
the console. Later tasks build on the same mechanism: the visual flow builder (T-009) edits the
chain, the low-code script policy (T-010) is one more policy type, the packet inspector (T-012)
shows a policy-by-policy trace, and consumers and plans (T-014) own the API keys.

## Decision

* **Chains are data.** An API's ordered chain is stored as JSON on the API (`apis.policies`):
  entries `{id, type, name, enabled, routes, config}`. Pydantic models
  (`apiedge.policies.config`) validate every type's configuration when the admin API saves it and
  again when the gateway loads it. The server assigns stable ids; the decision trace and the
  flow builder refer to them. `routes` limits an entry to some of the API's routes (by configured
  path); empty means every route. The chain is replaced as a whole
  (`PUT .../apis/{id}/policies`, `policy:read` / `policy:update`). A JSON column rather than a
  table keeps the whole chain one atomic, versionable document, which is what the flow builder
  edits; nothing queries individual policies.
* **Onion pipeline with a decision trace.** Policies run in order on the request; one may answer
  the request itself (401/403/429, mock, cache hit), which skips the rest and the upstream. The
  response passes back through the policies that ran, in reverse order, so CORS headers, rate
  limit headers and response transforms also apply to answers produced inside the chain. Every
  step appends a `TraceEntry` (policy id, type, phase, outcome, detail, duration) to the request
  context; the gateway hands context and status to registered trace listeners (T-012 will
  subscribe). Details never contain credentials.
* **Fail closed.** A stored entry that does not validate or whose secret cannot be decrypted
  becomes a placeholder that answers 503; a policy that raises answers a generic 500. An
  unusable authentication policy can therefore never let traffic through.
* **Secrets.** Secret fields (the JWT shared secret) are encrypted with the secrets box (AES-GCM,
  ADR 0003; AAD binds them to API, policy id and field) and are write-only in the admin API:
  responses return `null` plus `secrets_set`, and sending `null` keeps the stored value.
* **API keys (interim until T-014).** Keys belong to a product (`api_keys` table) and work for
  every API of that product with an `api-key` policy. A key is `ak_` plus 256 random bits, shown
  once; only its SHA-256 is stored (a fast hash is enough for a 256-bit random secret; no
  password-style stretching is needed) together with an 11-character display prefix. Keys can
  expire and be revoked; the gateway loads active keys with the snapshot and checks expiry per
  request, and the change notifier reloads it on revocation. New permissions `apikey:read` and
  `apikey:manage` (TenantAdmin, ProductOwner, APIDeveloper; Viewer reads). T-014 will attach
  keys to consumer applications with a nullable foreign key; the gateway then reports the
  consumer instead of the key name.
* **JWT.** Own verifier on pycryptodome primitives (no new dependency; `cryptography` cannot be
  used, ADR 0003): explicit algorithm allow-list, no `none`, no mixing of HS* with asymmetric
  algorithms in one policy (algorithm confusion), `crit` refused, RSA keys of 2048 bits or more,
  curve bound to the algorithm, `exp` required by default, `nbf`/`iss`/`aud` with a leeway of at
  most 300 s. Keys come from a shared secret, a PEM public key, or an https JWKS URL. JWKS
  documents are fetched with the gateway's SSRF-guarded client (connect-time address checks,
  no redirects), capped at 64 KiB, cached (default 5 min) and refreshed on an unknown `kid` at
  most every 30 s; `oct` keys in a JWKS are ignored. Unreachable keys answer 503.
* **Rate limits.** Fixed windows per policy and per consumer (falling back to the client
  address), per client address or per API. Redis (`INCR` + `EXPIRE`, window index in the key)
  when `APIEDGE_REDIS_URL` is set, so all gateway processes share counters; otherwise bounded
  in-process counters. If Redis fails, the limiter falls back to the in-process counters and
  logs a warning, so an outage neither blocks all traffic nor removes limits. Answers carry
  `RateLimit-Policy`, `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`; 429
  answers add `Retry-After`. Fixed windows were chosen over sliding logs for O(1) memory per key.
* **Client address.** The gateway uses `X-Forwarded-For` only when the direct peer is in
  `APIEDGE_GATEWAY_TRUSTED_PROXIES`, walking from the right past trusted proxies. It is a gateway
  setting, not a policy option, because the network layout is an operator concern.
* **CORS.** Preflights (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) are answered
  by the CORS policy of the route the browser asks about, before any other policy runs (browsers
  never send credentials on preflights), even if the route does not list `OPTIONS`. Refused
  preflights answer 403 without CORS headers. `*` with credentials is rejected at save time.
* **Cache.** Per-process LRU limited by total bytes (`APIEDGE_GATEWAY_CACHE_MAX_BYTES`). Only
  GET and HEAD; only cacheable statuses; responses with `no-store`, `no-cache`, `private`,
  `Set-Cookie` or a `Vary` on unconfigured headers are not stored; `max-age`/`s-maxage` can only
  shorten the policy TTL; request `no-cache` revalidates and `no-store` bypasses. Requests with
  credentials (an identity, `Authorization` or `Cookie`) bypass the cache unless
  `cache_authenticated` is set, and then the key includes the identity (or a hash of the
  credentials). The key also includes the policy configuration, path, raw query, `Accept` and
  `Accept-Encoding`. A shared (Redis) cache is left to a later task.
* **Transforms.** Request and response headers (set/remove, with `{consumer}`, `{request_id}`,
  `{client_ip}` placeholders), query parameters, and JSON body fields (dot paths). Headers the
  gateway manages (hop-by-hop, `Host`, `Content-Length`, `X-Forwarded-*`, `X-Request-ID`,
  response `Content-Encoding`) cannot be changed; values must be visible Latin-1. Response body
  transforms buffer at most `max_body_bytes` and skip encoded or larger bodies.

## Consequences

* The flow builder (T-009) edits the same chain document; script policies (T-010) are a new type.
* The packet inspector (T-012) registers a trace listener and gets the decision trace for free.
* T-014 moves API keys under consumers and plans (quotas per plan reuse the rate-limit store).
* Cache entries and in-process counters are per gateway process; operators who run several
  processes should configure Redis for exact rate limits.
