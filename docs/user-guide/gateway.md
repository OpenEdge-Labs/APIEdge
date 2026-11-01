# Calling APIs through the gateway

The gateway serves the [APIs](apis.md) you publish. It listens on its own port (default
`http://127.0.0.1:8081`, see `APIEDGE_GATEWAY_HOST` / `APIEDGE_GATEWAY_PORT`), separate from the
console. An API is reachable at

```
http://<gateway host>:<gateway port>/<tenant slug><base path><route path>
```

For tenant `acme`, base path `/orders` and route `GET /{id}`:
`curl http://127.0.0.1:8081/acme/orders/42`. The console shows this path as **Gateway** in the
API list for published and deprecated APIs (the admin API returns it as `gateway_path`).

## What is served

| API (and product) state | Gateway answer |
|---|---|
| API draft | 404, as if it did not exist |
| API published, product draft, published or deprecated | proxied |
| API deprecated, or product deprecated | proxied, response carries `Deprecation: true` |
| API retired, or product retired | 410 Gone |
| Tenant disabled, or unknown tenant | 404 |

Changes made in the console or admin API take effect without a restart, normally within a
fraction of a second (see [hot reload](#hot-reload)).

## Routing

* The longest matching base path wins; base paths match whole segments (`/orders` does not
  match `/ordersX`).
* The rest of the path must match a route: `{name}` matches one segment, a final `/*` matches the
  path itself and everything below it. A path that exists with other methods answers 405 with
  an `Allow` header. HEAD and OPTIONS are only accepted when the route lists them.
* The request is forwarded to `<upstream URL><rest of the path>?<query>`. With upstream
  `https://orders.internal/v2` and request `/acme/orders/42?x=1`, the upstream receives
  `GET /v2/42?x=1` with `Host: orders.internal`.
* Paths containing `.` or `..` segments (also percent-encoded) are refused with 400.

## Load balancing, timeouts and retries

* Requests are spread over the upstreams by weight (smooth weighted round-robin: weights 3 and 1
  give `a a b a` patterns, never long bursts).
* The API's timeout applies to connecting, sending and waiting for the answer. A timeout answers
  504; an unreachable upstream answers 502.
* Failed calls are retried on another upstream (`APIEDGE_GATEWAY_RETRIES`, default 1 retry):
  connection failures for every method (nothing was sent), and timeouts or 502/503/504 answers
  only for GET, HEAD, OPTIONS, PUT and DELETE. A POST or PATCH is never sent twice.
* Upstream redirects are returned to the client, never followed by the gateway.

## Headers and bodies

* Hop-by-hop headers (`Connection` and the headers it names, `Keep-Alive`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`, `Proxy-Authenticate`) are not forwarded
  in either direction. Other headers, including `Authorization` and cookies, pass through
  (authentication policies arrive with T-008).
* The gateway adds `X-Forwarded-For` (appended), `X-Forwarded-Host`, `X-Forwarded-Proto`,
  `X-Forwarded-Prefix` (`/<tenant><base path>`) and `X-Request-ID`. A client's `X-Request-ID` is
  kept if it is 1-128 characters of letters, digits and `. _ : -`; otherwise a new id is made.
  Every response carries the request id.
* Request bodies above `APIEDGE_GATEWAY_MAX_REQUEST_BODY_BYTES` (default 10 MiB) answer 413.

## Errors

Gateway errors are JSON and never include upstream or internal details:

```json
{"error": "bad_gateway", "message": "The upstream service could not be reached.", "request_id": "..."}
```

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request` | Dot segments in the path |
| 404 | `not_found` | Unknown tenant, API or route |
| 405 | `method_not_allowed` | Path exists, method does not |
| 410 | `api_retired` | Retired API or product |
| 413 | `payload_too_large` | Body over the limit |
| 502 | `bad_gateway` | Upstream unreachable, refused by the SSRF guard, or failed |
| 504 | `gateway_timeout` | Upstream did not answer within the API's timeout |

Responses from the upstream itself (including its own 4xx/5xx) are passed through unchanged.

## Security

* **SSRF at connect time:** every new upstream connection resolves the host again and checks
  all its addresses against the SSRF policy (`APIEDGE_SSRF_*`) before connecting to a checked
  address, so a DNS change after saving (DNS rebinding) cannot reach blocked addresses.
* **TLS:** HTTPS upstreams are always verified (TLS 1.2 or newer) against the public CA bundle,
  or against `APIEDGE_GATEWAY_CA_BUNDLE` for internal CAs. Verification cannot be switched off.

## Hot reload

The admin API publishes a change event after every committed change to a tenant, product, API,
upstream or route, and the gateway reloads its configuration from the database. In one process
(`apiedge run`) this is immediate. With several processes or hosts, set `APIEDGE_REDIS_URL` so the
event travels over Redis pub/sub; without Redis, other processes pick changes up with the periodic
reload (`APIEDGE_GATEWAY_RELOAD_INTERVAL_SECONDS`, default 30). If a reload fails, the gateway keeps
serving the previous configuration.

## Probes

`GET /-/healthz` (process alive) and `GET /-/readyz` (configuration loaded) on the gateway port.
