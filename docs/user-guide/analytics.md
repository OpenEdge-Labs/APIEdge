# Analytics Guide

APIEdge measures every request the gateway answers for a published API and shows the results on
the console's **Analytics** page. Design: [ADR 0008](../adr/0008-analytics.md).

## Who can see analytics

| Role | Access |
|---|---|
| TenantAdmin, Viewer, ProductOwner, APIDeveloper (tenant-wide) | All traffic of the tenant |
| Any of these roles granted for one product | Only that product's APIs |
| Consumer, users without `analytics:view` | No access (the page is hidden; the API answers 403) |

Analytics never cross tenants. Only identifiers and numbers are stored: no request or response
content, headers, query strings or client addresses.

## What is measured

For each request that reaches an API (including the gateway's own answers such as 404 for an
unknown route, 405, 410 for retired APIs, 413, 502 and 504):

- time (aggregated per minute), product, API, route (the configured route path, e.g.
  `/orders/{id}`; empty when no route matched), HTTP method, consumer, status code;
- latency from receiving the request to sending the last response byte;
- request and response body bytes.

Callers authenticated by a [policy](policies.md) are shown as `key:<API key name>` or
`jwt:<subject>`; unauthenticated traffic is shown as **(anonymous)**. Consumer applications with
plans and subscriptions (T-014) will replace the key names.

Requests whose path matches no API at all belong to no tenant; they are only counted in the
Prometheus metric `apiedge_gateway_unmatched_requests_total`.

## The dashboard

Open **Analytics** in the console and choose a time range (15 minutes to 30 days).

- **Tiles:** requests, error rate (4xx and 5xx responses / all requests), 4xx and 5xx counts,
  p50 / p95 / p99 latency, data in and out.
- **Chart:** one bar per time slot (1 minute for short ranges up to 1 day for 30 days) with
  errors in red, and the p95 latency line.
- **Top APIs**, **Status codes** and **Top consumers** tables. Click an API or a consumer to
  filter the whole page by it; remove a filter with the `x` on its chip. The consumer box filters
  by an exact consumer name.
- **Export CSV** downloads the data behind the page (same range and filters) at the chart's time
  resolution: one row per time slot, API, route, method, consumer and status, with counts,
  latency average / percentiles / maximum and bytes. Exports are recorded in the audit log
  (`analytics.export`).

Data appears after the gateway's next flush (every 10 seconds by default). Percentiles are
estimated from latency histograms (bucket bounds 5, 10, 25, 50, 100, 250, 500 ms, 1, 2.5, 5,
10 and 30 s), so they are accurate to within a bucket; counts, sums and maxima are exact.

## Admin API

| Route | Permission |
|---|---|
| `GET /api/v1/tenants/{tenant_id}/analytics/summary` | `analytics:view` |
| `GET /api/v1/tenants/{tenant_id}/analytics/export.csv` | `analytics:view` (audited) |

Query parameters (all optional): `start`, `end` (ISO 8601; default the last hour; at most 31
days), `product_id`, `api_id`, `consumer` (`consumer=` selects anonymous traffic). A
`product_id` outside the caller's products returns no data. Invalid ranges answer 422.

```
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/tenants/1/analytics/summary?start=2026-11-01T00:00:00Z&api_id=3"
```

The summary returns `totals`, `series` (per `step_seconds`), `status_codes`, `top_apis` (with
names; `null` for deleted APIs) and `top_consumers`.

## Prometheus

Set `APIEDGE_METRICS_TOKEN` (at least 16 characters) to enable `GET /metrics` on the console port
and scrape it with that bearer token:

```yaml
scrape_configs:
  - job_name: apiedge
    authorization:
      credentials: <APIEDGE_METRICS_TOKEN>
    static_configs:
      - targets: ["apiedge-host:8080"]
```

Metrics (labels `tenant` = tenant slug, `api_id`):

| Metric | Type |
|---|---|
| `apiedge_gateway_requests_total{tenant,api_id,method,status}` | counter |
| `apiedge_gateway_request_duration_seconds{tenant,api_id}` | histogram |
| `apiedge_gateway_request_bytes_total{tenant,api_id}` | counter |
| `apiedge_gateway_response_bytes_total{tenant,api_id}` | counter |
| `apiedge_gateway_unmatched_requests_total` | counter |

Without the token setting the endpoint answers 404; a missing or wrong token answers 401. The
metrics cover all tenants, so treat the token like an administrator credential.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `APIEDGE_ANALYTICS_FLUSH_INTERVAL_SECONDS` | `10` | How often the gateway writes aggregates (1-300) |
| `APIEDGE_ANALYTICS_RETENTION_DAYS` | `30` | Analytics older than this are deleted (1-3650) |
| `APIEDGE_METRICS_TOKEN` | unset | Bearer token that enables `GET /metrics` |
