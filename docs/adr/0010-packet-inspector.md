# ADR 0010: Packet inspector

- Status: accepted
- Date: 2026-11-02
- Task: T-012

## Context

Teams need to see what really went through the gateway for one API: the request and response,
timings, the upstream that answered and what each policy decided (T-008 records a decision trace
per request). Captured traffic contains credentials and personal data, can be large, and the
gateway and the admin API may run in separate processes or on separate hosts. Capture must
never slow down or break normal traffic, and must be bounded in memory and disk.

## Decision

1. **Capture sessions** (`capture_sessions`, migration 0007) are opt-in, per API, optionally
   narrowed to one route and/or one consumer, and time-boxed (`expires_at`, at most
   `APIEDGE_INSPECTOR_MAX_DURATION_MINUTES`). They can be stopped early and deleted. At most
   `APIEDGE_INSPECTOR_MAX_ACTIVE_SESSIONS` are active per tenant.
2. **The gateway records through its existing trace listener hook.** T-008's listener
   (`GatewayRuntime.trace_listeners`) now receives the final response instead of only its status
   and may return an `ExchangeTap` that sees the response body as it is streamed. The request
   context also carries the URL and headers as received, the upstream chosen, the number of
   attempts and the upstream time. Requests that do not reach a route (404/405 at matching,
   retired APIs) are not captured.
3. **Bounded everywhere.** Bodies are copied only up to the session's `max_body_bytes` (at most
   `APIEDGE_INSPECTOR_MAX_BODY_BYTES`); the request body only if the gateway read it. Copies go
   into an in-memory queue bounded in bytes (`APIEDGE_INSPECTOR_QUEUE_MAX_BYTES`); when it is
   full exchanges are dropped and counted, never blocking traffic. A background task (every
   `APIEDGE_INSPECTOR_POLL_INTERVAL_SECONDS`) reloads active sessions, writes the queue in a
   worker thread, keeps only the newest `max_exchanges` per session (ring buffer) and deletes
   sessions and their exchanges `APIEDGE_INSPECTOR_RETENTION_HOURS` after they ended.
4. **Storage in the database, encrypted.** `captured_exchanges` holds a filterable summary
   (method, path without query, route, status, consumer, timings, upstream) and the full exchange
   as JSON encrypted with the secrets box (AES-256-GCM, associated data
   `tenant:<id>/capture:<id>/exchange`). Starting a capture needs the secrets master key (409
   otherwise). The database is shared by every gateway and admin process, so capture works the
   same with one process or many.
5. **Masked by default, at read time.** The stored copy is complete so that a user holding
   `inspector:unmask` can see the original; every other path (detail, live view, HAR, replay
   result) masks `Authorization`, `Cookie`, `Set-Cookie`, API-key and other sensitive headers,
   sensitive query/form parameters and JSON keys, credentials inside text, plus names configured
   per session and in `APIEDGE_INSPECTOR_MASK_FIELDS`. Unmasked views and exports are audited.
6. **Live view with Server-Sent Events** (`GET .../exchanges/stream`), not WebSockets: one-way,
   works with the cookie session, the strict CSP (`connect-src 'self'`) and the CSRF model
   unchanged. The stream polls the database every second with its own short-lived tenant-bound
   sessions and ends after at most 5 minutes so that authorization is re-checked on reconnect
   (`Last-Event-ID` resumes).
7. **Replay** sends the request as it was forwarded (headers after the policy chain, body,
   query) to one of the API's **current** upstreams (the recorded one if it is still configured)
   through the SSRF-guarded client, after an explicit SSRF check. A request answered inside the
   gateway, or whose body was only partly captured, cannot be replayed. Replay needs
   `inspector:capture`; the answer is masked unless the caller also holds `inspector:unmask`.
8. **Permissions** (seeded in 0002): `inspector:view` (list, detail, live, masked HAR),
   `inspector:capture` (start, stop, delete, replay), `inspector:unmask`; each tenant-wide or per
   product.

## Consequences

- Capture has a cost only for requests that match an active session; other requests pay one
  dictionary lookup and a copy of the received header list.
- The live view has up to about one poll interval plus one second of latency.
- Retention runs in the gateway process; without a running gateway nothing new is captured and
  old captures wait for the next gateway start to be purged (or can be deleted in the console).
- Binary bodies are stored base64 and not inspected for secrets.
- Without the secrets master key the inspector is unavailable (fails closed).
