# ADR 0008: Gateway analytics and Prometheus metrics

- Status: accepted
- Date: 2026-11-01
- Task: T-013

## Context

Administrators need traffic, latency percentiles, error rates, status codes and top APIs and
consumers for a time range, filtered by API and consumer, with CSV export and a Prometheus
endpoint. APIEdge ships with SQLite by default (PostgreSQL optional) and must stay a single
installable process with no extra services. Percentiles cannot be summed, and several gateway
processes may write to one database later (T-026).

## Decision

1. **Collection in the gateway.** Every request that resolves to an API is measured once it is
   answered: tenant, product, API, configured route path, method, consumer, status, latency until
   the last response byte, request and response body bytes. No content, headers, query strings or
   client addresses are recorded. Requests that match no API are only counted (they belong to no
   tenant). Until consumers exist (T-014) the consumer is empty ("anonymous").
2. **Pre-aggregation in memory.** `apiedge.analytics.metrics.MetricsCollector` aggregates per
   one-minute bucket and dimension combination, with a fixed 13-bucket latency histogram
   (5 ms ... 30 s, plus overflow) and the maximum latency.
3. **Insert-only flush.** A gateway task flushes the aggregates every
   `APIEDGE_ANALYTICS_FLUSH_INTERVAL_SECONDS` (default 10) and at shutdown into
   `analytics_buckets` (migration 0005). Rows are never updated, so several processes can write
   without coordination; queries sum them. Rows of deleted tenants are dropped; on database
   errors aggregates are kept (bounded) and retried. Rows older than
   `APIEDGE_ANALYTICS_RETENTION_DAYS` (default 30) are purged at most hourly. `product_id` and
   `api_id` have no foreign keys so history survives API deletion; the tenant foreign key removes
   a deleted tenant's analytics.
4. **Percentiles from merged histograms.** Queries `SUM` the histogram columns per group in SQL
   and estimate p50/p95/p99 by linear interpolation inside the bucket, capped at the observed
   maximum. Accuracy is bounded by the bucket width, which is acceptable for dashboards.
5. **Admin API.** `GET /tenants/{id}/analytics/summary` and `GET .../export.csv` need
   `analytics:view` tenant-wide or for a product (`require_any`); product-scoped callers only see
   their products' rows. Time ranges are at most 31 days; the series step is chosen to keep at
   most 120 points (1 min ... 1 day, aligned to the epoch). CSV cells that start with a formula
   character are prefixed with `'` (CSV injection) and every export is audit-logged.
6. **Prometheus.** `GET /metrics` on the console port serves cumulative counters and latency
   histograms per tenant and API in the text exposition format, written without a new dependency.
   It is off (404) unless `APIEDGE_METRICS_TOKEN` (at least 16 characters) is set and then needs
   `Authorization: Bearer <token>` (constant-time comparison). The collector is shared in-process
   by `apiedge run`.

## Consequences

- No new dependency and no extra service; works on SQLite and PostgreSQL.
- Dashboards lag real traffic by up to the flush interval.
- Percentiles are estimates; the CSV gives exact counts, sums and maxima.
- Insert-only rows can grow to one row per active dimension combination per flush; retention
  bounds the table. A roll-up to coarser buckets can be added later if needed (T-026/T-028).
- `/metrics` reflects the gateway in the same process only; separate gateway processes (T-026)
  will need their own endpoint.
