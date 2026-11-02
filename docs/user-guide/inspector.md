# Packet Inspector Guide

The packet inspector records what passes through the gateway for one API so you can debug it:
the request and response (line, headers, body), timings, the upstream that answered and a
policy-by-policy trace of what the gateway decided. Capture is **opt-in, time-boxed and
bounded**, and captured data is **masked by default**.

## Permissions

| Permission | Allows |
|---|---|
| `inspector:view` | See capture sessions and captured exchanges (masked), use the live view, export masked HAR |
| `inspector:capture` | Start, stop and delete captures; replay a captured request |
| `inspector:unmask` | See exchanges, HAR exports and replay answers unmasked (every use is audit-logged) |

Each can be granted for the whole tenant or for single products. Built-in roles:
TenantAdmin has all three; ProductOwner and APIDeveloper have view and capture; Viewer has view.

## Starting a capture

Console: **Packet inspector > New capture**.

| Field | Meaning |
|---|---|
| Product, API | The API whose traffic is captured |
| Route | Only requests matched to this route (default: all routes) |
| Consumer | Only this consumer, for example `key:mobile` or `jwt:alice` (default: anyone) |
| Duration (minutes) | Capture stops automatically afterwards (server limit `APIEDGE_INSPECTOR_MAX_DURATION_MINUTES`, default 60) |
| Keep newest | Ring buffer: only the newest N exchanges are kept (limit `APIEDGE_INSPECTOR_MAX_EXCHANGES`, default 1000) |
| Max body bytes | Request and response bodies are cut after this many bytes (limit `APIEDGE_INSPECTOR_MAX_BODY_BYTES`, default 64 KiB) |
| Extra fields to mask | Additional JSON field, header or parameter names to mask, for example `ssn, card_number` |

The gateway picks the capture up within about a second. **Stop** ends it early; **Delete**
removes it with all its exchanges. Exchanges are deleted automatically
`APIEDGE_INSPECTOR_RETENTION_HOURS` (default 24) after the capture ended. A tenant may have at
most `APIEDGE_INSPECTOR_MAX_ACTIVE_SESSIONS` (default 10) active captures.

Capture needs the secrets master key (`APIEDGE_SECRET_KEY` or the key file created by
`apiedge init`): exchanges are stored encrypted.

## Browsing exchanges

**Captured exchanges** lists the newest exchanges first. Filter by capture, method, status class
(2xx-5xx), part of the path and consumer. Tick **Live** to have new exchanges appear as they are
captured.

Click a path to open the detail pane:

- request id, status and who answered (`upstream`, `policy` or `gateway`);
- timings: total (until the last response byte), upstream (until its response headers) and the
  time spent in policies;
- the upstream URL and the attempt number (retries);
- the **policy trace**: each policy, phase (request/response), outcome (`pass`, `modify`,
  `skip`, `reject`, `respond`, `error`), detail and duration;
- the request as received (URL, headers, body) and the response as sent.

The request body is shown as the gateway forwarded it (after transforms); it is "not captured"
when the gateway never read it (for example a request rejected by an authentication policy
before the body was needed). Bodies cut at the size limit say so.

Requests that do not match any route of the API (404/405) are not captured.

## Masking

By default the inspector masks:

- the `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and `X-API-Key` headers and
  any header whose name contains words such as `token`, `secret`, `password`, `api-key`,
  `session`, `signature` or `credential`;
- query and form parameters and JSON keys with such names, at any depth;
- credentials inside text (bearer/basic tokens, JWTs, `key=value` pairs, PEM private keys);
- the names you list in the capture and in `APIEDGE_INSPECTOR_MASK_FIELDS`.

Users with `inspector:unmask` see **Show unmasked**; each unmasked view is written to the audit
log (`inspector.exchange.unmask`).

## HAR export

**HAR** downloads the capture (newest 1000 exchanges) as a HAR 1.2 file that browsers' developer
tools and HTTP tools can open. The policy trace, request id, upstream and consumer are included
as `_apiedge` fields. **HAR (unmasked)** needs `inspector:unmask`. Exports are audit-logged
(`inspector.har.export`).

## Replay

**Replay** sends a captured request again to the API's upstream: same method, path, query,
headers (as forwarded after the policy chain) and body, plus an `X-APIEdge-Replay-Of` header with
the original request id. It goes to one of the API's current upstreams, never to an address
taken from the request, and through the same SSRF guard as the gateway. Requests answered by the
gateway itself (mock, rejection) and requests whose body was cut cannot be replayed. Replay needs
`inspector:capture` and is audit-logged (`inspector.exchange.replay`); the answer is masked
unless you hold `inspector:unmask`.

## Admin API

All routes are under `/api/v1/tenants/{tenant_id}/inspector`:

| Route | Permission |
|---|---|
| `GET /sessions` | `inspector:view` |
| `POST /sessions` (`api_id`, `route`, `consumer`, `duration_minutes`, `max_exchanges`, `max_body_bytes`, `mask_fields`) | `inspector:capture` |
| `POST /sessions/{id}/stop`, `DELETE /sessions/{id}` | `inspector:capture` |
| `GET /sessions/{id}/har[?unmasked=true]` | `inspector:view` (+ `inspector:unmask`) |
| `GET /exchanges?session_id=&api_id=&method=&status=&status_class=&path=&consumer=&before_id=&after_id=&limit=` | `inspector:view` |
| `GET /exchanges/stream?...&after_id=&timeout=` (Server-Sent Events, `exchange` events) | `inspector:view` |
| `GET /exchanges/{id}[?unmasked=true]` | `inspector:view` (+ `inspector:unmask`) |
| `POST /exchanges/{id}/replay[?unmasked=true]` | `inspector:capture` (+ `inspector:unmask`) |

Example: capture `/orders` for five minutes and follow it live:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"api_id": 3, "duration_minutes": 5}' \
  http://127.0.0.1:8080/api/v1/tenants/1/inspector/sessions
curl -N -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/tenants/1/inspector/exchanges/stream"
```

## Limits and resource use

- Only requests that match an active capture are copied; other traffic is not affected.
- The gateway holds at most `APIEDGE_INSPECTOR_QUEUE_MAX_BYTES` (default 16 MiB) of exchanges not
  yet written; beyond that exchanges are dropped rather than slowing traffic down.
- Disk use per capture is bounded by *Keep newest* x *Max body bytes* x 2 (plus headers).
- Captured traffic lives in the APIEdge database only, encrypted. Do not export unmasked HAR
  files into tickets or chats.
