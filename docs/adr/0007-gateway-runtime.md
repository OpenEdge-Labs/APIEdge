# ADR 0007: Gateway runtime

- Status: accepted
- Date: 2026-11-01
- Task: T-007

## Context

T-007 turns the configuration of ADR 0006 into live traffic: proxy published APIs with timeouts,
retries, load balancing and TLS, reload configuration without a restart (Redis pub/sub or
in-process), and enforce the deprecated and retired lifecycle states. Base paths are unique per
tenant only, so a request must name its tenant. Upstream URLs are SSRF-checked when saved, but DNS
can change afterwards.

## Decision

* **Separate data-plane app and port.** `apiedge.gateway.app.create_gateway_app` is a Starlette
  app served on `APIEDGE_GATEWAY_PORT` (default 8081, loopback by default), next to the console
  and admin API on `APIEDGE_PORT`. `apiedge run` serves both in one event loop. The data plane
  does not get the console's cookie, CSRF and CSP middleware, and console paths cannot shadow API
  paths.
* **Tenant in the path.** Requests are addressed as `/<tenant slug><base path><route path>`
  (the organisation-prefix style used by several enterprise gateways; no wildcard DNS needed).
  Unknown tenants, inactive tenants, unknown paths and draft APIs all answer the same 404.
  Gateway probes live under `/-/` (`/-/healthz`, `/-/readyz`), which no tenant slug can use.
* **Routing snapshot.** An immutable snapshot (tenant slug -> APIs, longest base path first) is
  built from the database in a worker thread and swapped atomically. Route paths compile to
  anchored regular expressions (`{name}` is one segment, a final `/*` matches the path and
  everything below). A path that matches with another method answers 405 with `Allow`.
* **Lifecycle.** Published APIs of products that are not retired are served; deprecated APIs (or
  APIs of a deprecated product) are served with `Deprecation: true`; retired APIs and every API of
  a retired product answer 410 Gone. A precise deprecation date (RFC 9745 form) needs a stored
  deprecation date and is left to a later task.
* **Hot reload.** A SQLAlchemy `after_commit` hook on the admin API's session factory publishes a
  data-less event when a tenant, product, API, upstream or route changed. `ConfigBus` delivers it
  in-process; `RedisConfigBus` (when `APIEDGE_REDIS_URL` is set) also publishes on the
  `apiedge:config` channel and listens to it, reconnecting after errors and reloading once on every
  (re)subscription. A periodic reload (`APIEDGE_GATEWAY_RELOAD_INTERVAL_SECONDS`, default 30 s)
  is the safety net. Events carry no data, so a lost or duplicated event cannot install a wrong
  configuration. A failed reload keeps the previous snapshot. The `redis` client (MIT) is a
  runtime dependency; a Redis server stays optional.
* **Connect-time SSRF guard.** The httpx connection pool uses `GuardedNetworkBackend`: each new
  TCP connection resolves the host, checks every resolved address against the SSRF policy and
  connects to a checked address. The request URL keeps the host name, so `Host`, TLS SNI and
  certificate verification use the real name and pooled connections are keyed by it. This
  defeats DNS rebinding without rewriting URLs. Redirects are passed through, never followed;
  proxy environment variables are ignored.
* **Load balancing, timeouts, retries, TLS (minimal; full versions in T-025).** Smooth weighted
  round-robin over the API's upstreams (deterministic, interleaved by weight). The API's
  `timeout_ms` applies to connect, write, read and pool waits. Retries
  (`APIEDGE_GATEWAY_RETRIES`, default 1) go to another upstream when possible: connection
  failures (including SSRF refusals) for every method because nothing was sent; timeouts,
  transport errors and 502/503/504 answers only for idempotent methods (GET, HEAD, OPTIONS, PUT,
  DELETE). TLS to upstreams always verifies certificates (TLS 1.2+), against the public CA
  bundle or `APIEDGE_GATEWAY_CA_BUNDLE`; there is deliberately no switch to disable verification.
* **Headers and bodies.** Hop-by-hop headers (and headers named in `Connection`) are not
  forwarded in either direction. `X-Forwarded-For` is appended to; `X-Forwarded-Host`,
  `X-Forwarded-Proto`, `X-Forwarded-Prefix` and `X-Request-ID` are set by the gateway (a valid
  client request id is kept). Request bodies are buffered up to
  `APIEDGE_GATEWAY_MAX_REQUEST_BODY_BYTES` (413 beyond, checked on the declared length and while
  reading); responses are streamed unchanged. Paths with `.` or `..` segments are refused (400).
* **Errors.** The gateway's own errors are fixed JSON documents (`error`, `message`,
  `request_id`) without exception text, host names or addresses; details go to the log only.

## Consequences

* T-008 adds the policy pipeline between matching and forwarding; T-012 and T-013 hook into the
  same request path for capture and metrics.
* T-025 extends load balancing (more algorithms, health checks, circuit breaker), retry policies
  and per-API TLS profiles (client certificates, custom trust).
* Multi-process deployments without Redis converge through the periodic reload.
