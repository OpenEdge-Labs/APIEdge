# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Per-request gateway metrics (T-013, ADR 0008).

The gateway calls :meth:`MetricsCollector.record` once per request that resolved to an API.
The collector keeps two in-memory views:

* pending one-minute aggregates keyed by (minute, tenant, product, API, route, method, consumer,
  status), drained by :meth:`flush` into ``analytics_buckets`` rows (insert-only, so several
  gateway processes can share one database), and
* cumulative counters and latency histograms per (tenant, API) for the Prometheus text exposition
  served at ``/metrics`` (:meth:`prometheus_text`).

Latencies are kept as fixed-bucket histograms, so percentiles can be merged across rows and
estimated later (:func:`percentile`). No request content, header or client address is recorded.
"""

from __future__ import annotations

import bisect
import logging
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.models import AnalyticsBucket, Tenant

log = logging.getLogger("apiedge.analytics")

# Upper bounds (ms) of the latency histogram; one more bucket counts everything slower.
LATENCY_BOUNDS_MS: tuple[float, ...] = (
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    30000,
)
HIST_SIZE = len(LATENCY_BOUNDS_MS) + 1
HIST_COLUMNS = tuple(f"h{i}" for i in range(HIST_SIZE))
BUCKET_SECONDS = 60
MAX_PENDING = 50_000  # aggregate keys kept while flushes fail


def latency_bucket(latency_ms: float) -> int:
    """Index of the histogram bucket for ``latency_ms`` (bounds are inclusive upper bounds)."""
    return bisect.bisect_left(LATENCY_BOUNDS_MS, latency_ms)


def percentile(hist: Sequence[int], q: float, max_ms: float | None = None) -> float | None:
    """Estimate the ``q`` quantile (0..1) from bucket counts by linear interpolation.

    The open-ended last bucket is interpolated up to ``max_ms`` (the slowest request seen), or
    reported as its lower bound when that is unknown. ``None`` when there are no requests.
    """
    total = sum(hist)
    if total <= 0:
        return None
    rank = q * total
    seen = 0
    for i, count in enumerate(hist):
        if count <= 0:
            continue
        if seen + count >= rank:
            lower = LATENCY_BOUNDS_MS[i - 1] if i > 0 else 0.0
            if i < len(LATENCY_BOUNDS_MS):
                upper = LATENCY_BOUNDS_MS[i]
            else:
                upper = max(max_ms, lower) if max_ms is not None else lower
            if max_ms is not None:
                upper = min(upper, max(max_ms, lower))
            fraction = (rank - seen) / count
            return round(lower + (upper - lower) * fraction, 3)
        seen += count
    return None  # pragma: no cover - unreachable for a non-empty histogram


@dataclass(frozen=True)
class RequestRecord:
    """One answered gateway request (only identifiers and numbers, no content)."""

    tenant_id: int
    tenant_slug: str
    product_id: int
    api_id: int
    route: str
    method: str
    status: int
    latency_ms: float
    bytes_in: int
    bytes_out: int
    consumer: str = ""
    at: float = field(default_factory=time.time)


@dataclass
class _Agg:
    requests: int = 0
    latency_sum_ms: float = 0.0
    latency_max_ms: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    hist: list[int] = field(default_factory=lambda: [0] * HIST_SIZE)

    def add(self, rec: RequestRecord) -> None:
        self.requests += 1
        self.latency_sum_ms += rec.latency_ms
        self.latency_max_ms = max(self.latency_max_ms, rec.latency_ms)
        self.bytes_in += rec.bytes_in
        self.bytes_out += rec.bytes_out
        self.hist[latency_bucket(rec.latency_ms)] += 1


_Key = tuple[int, int, int, int, str, str, str, int]  # minute, tenant, product, api, ...
_PromKey = tuple[str, int, str, int]  # tenant slug, api id, method, status
_PromHistKey = tuple[str, int]  # tenant slug, api id


class MetricsCollector:
    """Thread-safe in-memory metrics shared by the gateway, the flusher and ``/metrics``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[_Key, _Agg] = {}
        self._requests: dict[_PromKey, int] = {}
        self._latency: dict[_PromHistKey, _Agg] = {}
        self._unmatched = 0
        self._last_purge = 0.0

    def record(self, rec: RequestRecord) -> None:
        minute = int(rec.at // BUCKET_SECONDS) * BUCKET_SECONDS
        key: _Key = (
            minute,
            rec.tenant_id,
            rec.product_id,
            rec.api_id,
            rec.route[:500],
            rec.method[:10],
            rec.consumer[:128],
            rec.status,
        )
        prom: _PromKey = (rec.tenant_slug, rec.api_id, rec.method, rec.status)
        with self._lock:
            self._pending.setdefault(key, _Agg()).add(rec)
            self._requests[prom] = self._requests.get(prom, 0) + 1
            self._latency.setdefault((rec.tenant_slug, rec.api_id), _Agg()).add(rec)

    def record_unmatched(self) -> None:
        """A request that matched no API (only counted; it belongs to no tenant)."""
        with self._lock:
            self._unmatched += 1

    def drain(self) -> dict[_Key, _Agg]:
        with self._lock:
            pending, self._pending = self._pending, {}
        return pending

    def flush(self, factory: sessionmaker[Session], retention_days: int | None = None) -> int:
        """Write pending aggregates as new rows; purge expired rows at most hourly.

        Blocking (database I/O): call it from a worker thread. Rows of tenants deleted in the
        meantime are dropped. On a database error the drained aggregates are put back (up to
        ``MAX_PENDING`` keys) so the next flush retries them.
        """
        pending = self.drain()
        now = time.time()
        purge = retention_days is not None and now - self._last_purge >= 3600
        if not pending and not purge:
            return 0
        try:
            with factory() as session:
                tenant_ids = sorted({key[1] for key in pending})
                existing = (
                    set(session.scalars(select(Tenant.id).where(Tenant.id.in_(tenant_ids))))
                    if tenant_ids
                    else set()
                )
                rows = [_row(key, agg) for key, agg in pending.items() if key[1] in existing]
                session.add_all(rows)
                if purge and retention_days is not None:
                    cutoff = int(now) - retention_days * 86400
                    session.execute(
                        delete(AnalyticsBucket).where(AnalyticsBucket.bucket_start < cutoff)
                    )
                session.commit()
        except Exception:
            log.exception("analytics flush failed; will retry")
            self._restore(pending)
            return 0
        if purge:
            self._last_purge = now
        return len(rows)

    def _restore(self, pending: dict[_Key, _Agg]) -> None:
        with self._lock:
            for key, agg in pending.items():
                if key not in self._pending and len(self._pending) >= MAX_PENDING:
                    continue  # bounded memory while the database is unavailable
                cur = self._pending.setdefault(key, _Agg())
                cur.requests += agg.requests
                cur.latency_sum_ms += agg.latency_sum_ms
                cur.latency_max_ms = max(cur.latency_max_ms, agg.latency_max_ms)
                cur.bytes_in += agg.bytes_in
                cur.bytes_out += agg.bytes_out
                cur.hist = [a + b for a, b in zip(cur.hist, agg.hist, strict=True)]

    def prometheus_text(self) -> str:
        """Prometheus text exposition format 0.0.4 of the cumulative counters."""
        with self._lock:
            requests = sorted(self._requests.items())
            latency = sorted(
                (k, (v.requests, v.latency_sum_ms, list(v.hist), v.bytes_in, v.bytes_out))
                for k, v in self._latency.items()
            )
            unmatched = self._unmatched
        out = [
            "# HELP apiedge_gateway_requests_total Requests answered by the gateway for an API.",
            "# TYPE apiedge_gateway_requests_total counter",
        ]
        for (tenant, api_id, method, status), count in requests:
            labels = _labels(tenant=tenant, api_id=str(api_id), method=method, status=str(status))
            out.append(f"apiedge_gateway_requests_total{{{labels}}} {count}")
        out += [
            "# HELP apiedge_gateway_request_duration_seconds Gateway request latency.",
            "# TYPE apiedge_gateway_request_duration_seconds histogram",
        ]
        for (tenant, api_id), (count, total_ms, hist, _bin, _bout) in latency:
            base = _labels(tenant=tenant, api_id=str(api_id))
            cumulative = 0
            for bound, n in zip(LATENCY_BOUNDS_MS, hist[:-1], strict=True):
                cumulative += n
                le = _format_float(bound / 1000)
                out.append(
                    f'apiedge_gateway_request_duration_seconds_bucket{{{base},le="{le}"}} '
                    f"{cumulative}"
                )
            out.append(
                f'apiedge_gateway_request_duration_seconds_bucket{{{base},le="+Inf"}} {count}'
            )
            out.append(
                f"apiedge_gateway_request_duration_seconds_sum{{{base}}} "
                f"{_format_float(total_ms / 1000)}"
            )
            out.append(f"apiedge_gateway_request_duration_seconds_count{{{base}}} {count}")
        for name, idx, help_text in (
            ("apiedge_gateway_request_bytes_total", 3, "Request body bytes received for an API."),
            ("apiedge_gateway_response_bytes_total", 4, "Response body bytes sent for an API."),
        ):
            out += [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
            for (tenant, api_id), values in latency:
                labels = _labels(tenant=tenant, api_id=str(api_id))
                out.append(f"{name}{{{labels}}} {values[idx]}")
        out += [
            "# HELP apiedge_gateway_unmatched_requests_total Requests that matched no API.",
            "# TYPE apiedge_gateway_unmatched_requests_total counter",
            f"apiedge_gateway_unmatched_requests_total {unmatched}",
        ]
        return "\n".join(out) + "\n"


def _row(key: _Key, agg: _Agg) -> AnalyticsBucket:
    minute, tenant_id, product_id, api_id, route, method, consumer, status = key
    return AnalyticsBucket(
        bucket_start=minute,
        tenant_id=tenant_id,
        product_id=product_id,
        api_id=api_id,
        route=route,
        method=method,
        consumer=consumer,
        status_code=status,
        requests=agg.requests,
        latency_sum_ms=agg.latency_sum_ms,
        latency_max_ms=agg.latency_max_ms,
        bytes_in=agg.bytes_in,
        bytes_out=agg.bytes_out,
        **dict(zip(HIST_COLUMNS, agg.hist, strict=True)),
    )


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**labels: str) -> str:
    return ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())


def _format_float(value: float) -> str:
    return repr(float(value))
