# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Reading ``analytics_buckets`` for dashboards and CSV export (T-013, ADR 0008).

Every query runs on a session bound to the caller's tenant (``apiedge.db.tenancy``), so rows of
other tenants are never read. Product-scoped callers additionally pass the set of products they
may see. Sums are computed by the database; percentiles are estimated in Python from the merged
latency histograms.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import ColumnElement, case, func, select
from sqlalchemy.orm import Session

from apiedge.analytics.metrics import BUCKET_SECONDS, HIST_COLUMNS, HIST_SIZE, percentile
from apiedge.db.models import AnalyticsBucket as B

STEPS = (60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400)
MAX_POINTS = 120


def choose_step(start: int, end: int) -> int:
    """The smallest step that keeps a time series at or below ``MAX_POINTS`` points."""
    span = max(end - start, BUCKET_SECONDS)
    for step in STEPS:
        if span / step <= MAX_POINTS:
            return step
    return STEPS[-1]


@dataclass(frozen=True)
class Filters:
    start: int  # epoch seconds, inclusive
    end: int  # epoch seconds, exclusive
    product_ids: frozenset[int] | None = None  # None: every product of the tenant
    api_id: int | None = None
    consumer: str | None = None

    def where(self) -> list[ColumnElement[bool]]:
        conds: list[ColumnElement[bool]] = [B.bucket_start >= self.start, B.bucket_start < self.end]
        if self.product_ids is not None:
            conds.append(B.product_id.in_(sorted(self.product_ids)))
        if self.api_id is not None:
            conds.append(B.api_id == self.api_id)
        if self.consumer is not None:
            conds.append(B.consumer == self.consumer)
        return conds


@dataclass
class Stats:
    requests: int = 0
    client_errors: int = 0
    server_errors: int = 0
    latency_sum_ms: float = 0.0
    latency_max_ms: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    hist: list[int] = field(default_factory=lambda: [0] * HIST_SIZE)

    def merge(self, other: Stats) -> None:
        self.requests += other.requests
        self.client_errors += other.client_errors
        self.server_errors += other.server_errors
        self.latency_sum_ms += other.latency_sum_ms
        self.latency_max_ms = max(self.latency_max_ms, other.latency_max_ms)
        self.bytes_in += other.bytes_in
        self.bytes_out += other.bytes_out
        self.hist = [a + b for a, b in zip(self.hist, other.hist, strict=True)]

    @property
    def errors(self) -> int:
        return self.client_errors + self.server_errors

    @property
    def error_rate(self) -> float:
        return round(self.errors / self.requests, 6) if self.requests else 0.0

    @property
    def latency_avg_ms(self) -> float | None:
        return round(self.latency_sum_ms / self.requests, 3) if self.requests else None

    def p(self, q: float) -> float | None:
        return percentile(self.hist, q, self.latency_max_ms)


def _measures() -> list[Any]:
    return [
        func.sum(B.requests),
        func.sum(case((B.status_code.between(400, 499), B.requests), else_=0)),
        func.sum(case((B.status_code >= 500, B.requests), else_=0)),
        func.sum(B.latency_sum_ms),
        func.max(B.latency_max_ms),
        func.sum(B.bytes_in),
        func.sum(B.bytes_out),
        *(func.sum(getattr(B, c)) for c in HIST_COLUMNS),
    ]


def _stats(values: Sequence[Any]) -> Stats:
    return Stats(
        requests=int(values[0] or 0),
        client_errors=int(values[1] or 0),
        server_errors=int(values[2] or 0),
        latency_sum_ms=float(values[3] or 0),
        latency_max_ms=float(values[4] or 0),
        bytes_in=int(values[5] or 0),
        bytes_out=int(values[6] or 0),
        hist=[int(v or 0) for v in values[7 : 7 + HIST_SIZE]],
    )


def grouped(
    session: Session, filters: Filters, dims: Sequence[Any], limit: int | None = None
) -> list[tuple[tuple[Any, ...], Stats]]:
    """Stats per combination of ``dims`` (columns of ``analytics_buckets``)."""
    stmt = select(*dims, *_measures()).where(*filters.where())
    if dims:
        stmt = stmt.group_by(*dims)
    if limit is not None:
        stmt = stmt.limit(limit)
    out = []
    for row in session.execute(stmt):
        stats = _stats(row[len(dims) :])
        if stats.requests:
            out.append((tuple(row[: len(dims)]), stats))
    return out


def fold(rows: Iterable[tuple[tuple[Any, ...], Stats]], step: int) -> dict[tuple[Any, ...], Stats]:
    """Re-bucket rows whose first key part is ``bucket_start`` into ``step``-second buckets
    aligned to the epoch (so a bucket's time is the same whatever range is asked for)."""
    out: dict[tuple[Any, ...], Stats] = {}
    for key, stats in rows:
        t = (int(key[0]) // step) * step
        out.setdefault((t, *key[1:]), Stats()).merge(stats)
    return out


def summarize(session: Session, filters: Filters, top: int = 10) -> dict[str, Any]:
    step = choose_step(filters.start, filters.end)
    totals_rows = grouped(session, filters, [])
    totals = totals_rows[0][1] if totals_rows else Stats()
    series = fold(grouped(session, filters, [B.bucket_start]), step)
    statuses = grouped(session, filters, [B.status_code])
    apis = grouped(session, filters, [B.api_id, B.product_id])
    consumers = grouped(session, filters, [B.consumer])
    apis.sort(key=lambda r: (-r[1].requests, r[0][0]))
    consumers.sort(key=lambda r: (-r[1].requests, r[0][0]))
    return {
        "step_seconds": step,
        "totals": stats_view(totals),
        "series": [
            {"t": key[0], **stats_view(stats, brief=True)} for key, stats in sorted(series.items())
        ],
        "status_codes": [
            {"status": int(key[0]), "requests": stats.requests}
            for key, stats in sorted(statuses, key=lambda r: int(r[0][0]))
        ],
        "top_apis": [
            {"api_id": int(key[0]), "product_id": int(key[1]), **stats_view(stats, brief=True)}
            for key, stats in apis[:top]
        ],
        "top_consumers": [
            {"consumer": str(key[0]), **stats_view(stats, brief=True)}
            for key, stats in consumers[:top]
        ],
    }


def stats_view(stats: Stats, brief: bool = False) -> dict[str, Any]:
    view: dict[str, Any] = {
        "requests": stats.requests,
        "errors": stats.errors,
        "error_rate": stats.error_rate,
        "latency_p50_ms": stats.p(0.5),
        "latency_p95_ms": stats.p(0.95),
        "latency_p99_ms": stats.p(0.99),
    }
    if not brief:
        view.update(
            client_errors=stats.client_errors,
            server_errors=stats.server_errors,
            latency_avg_ms=stats.latency_avg_ms,
            latency_max_ms=round(stats.latency_max_ms, 3) if stats.requests else None,
            bytes_in=stats.bytes_in,
            bytes_out=stats.bytes_out,
        )
    return view


EXPORT_DIMS = (B.product_id, B.api_id, B.route, B.method, B.consumer, B.status_code)


def export_rows(
    session: Session, filters: Filters, max_source_rows: int
) -> tuple[int, list[tuple[tuple[Any, ...], Stats]]] | None:
    """(step, rows keyed by (time, *EXPORT_DIMS)), or None if the range holds too many rows."""
    step = choose_step(filters.start, filters.end)
    rows = grouped(session, filters, [B.bucket_start, *EXPORT_DIMS], limit=max_source_rows + 1)
    if len(rows) > max_source_rows:
        return None
    folded = fold(rows, step)
    return step, sorted(folded.items(), key=lambda kv: kv[0])
