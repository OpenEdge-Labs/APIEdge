# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Analytics building blocks (T-013): histogram buckets, percentile estimation, the collector's
minute aggregation and failure handling, the Prometheus exposition, steps and CSV escaping."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from apiedge.admin.analytics import csv_cell
from apiedge.analytics.metrics import (
    HIST_COLUMNS,
    HIST_SIZE,
    LATENCY_BOUNDS_MS,
    MetricsCollector,
    RequestRecord,
    latency_bucket,
    percentile,
)
from apiedge.analytics.query import Stats, choose_step, fold
from apiedge.config import Settings
from apiedge.db.base import make_engine, make_session_factory, run_migrations
from apiedge.db.models import AnalyticsBucket, Tenant


def _rec(**kw: object) -> RequestRecord:
    base: dict[str, object] = {
        "tenant_id": 1,
        "tenant_slug": "acme",
        "product_id": 2,
        "api_id": 3,
        "route": "/x",
        "method": "GET",
        "status": 200,
        "latency_ms": 12.0,
        "bytes_in": 0,
        "bytes_out": 10,
        "at": 1_699_999_985.0,
    }
    base.update(kw)
    return RequestRecord(**base)  # type: ignore[arg-type]


def test_model_has_one_column_per_histogram_bucket() -> None:
    assert len(HIST_COLUMNS) == HIST_SIZE == len(LATENCY_BOUNDS_MS) + 1
    assert all(hasattr(AnalyticsBucket, c) for c in HIST_COLUMNS)


def test_latency_bucket_bounds_are_inclusive() -> None:
    assert latency_bucket(0) == 0
    assert latency_bucket(5) == 0
    assert latency_bucket(5.01) == 1
    assert latency_bucket(30000) == len(LATENCY_BOUNDS_MS) - 1
    assert latency_bucket(10**7) == len(LATENCY_BOUNDS_MS)


def test_percentile_estimation() -> None:
    assert percentile([0] * HIST_SIZE, 0.5) is None
    hist = [0] * HIST_SIZE
    hist[2] = 10  # all requests in (10, 25] ms
    assert percentile(hist, 0.5) == 17.5
    assert percentile(hist, 0.99, max_ms=20.0) == pytest.approx(19.9)  # capped at the slowest
    slow = [0] * HIST_SIZE
    slow[-1] = 4  # all slower than the last bound
    assert percentile(slow, 0.5) == LATENCY_BOUNDS_MS[-1]
    assert percentile(slow, 1.0, max_ms=60000.0) == 60000.0
    mixed = [0] * HIST_SIZE
    mixed[0], mixed[4] = 90, 10
    assert percentile(mixed, 0.5) == pytest.approx(2.778, abs=1e-3)
    assert 50 < percentile(mixed, 0.95) <= 100  # type: ignore[operator]


def test_collector_aggregates_per_minute_and_dimension() -> None:
    c = MetricsCollector()
    c.record(_rec(latency_ms=4))
    c.record(_rec(latency_ms=40, bytes_in=7, at=1_700_000_039.0))
    c.record(_rec(at=1_700_000_040.0))  # next minute
    c.record(_rec(status=404))
    pending = c.drain()
    assert c.drain() == {}
    assert len(pending) == 3
    first = pending[(1_699_999_980, 1, 2, 3, "/x", "GET", "", 200)]
    assert first.requests == 2 and first.bytes_in == 7 and first.latency_max_ms == 40
    assert first.hist[0] == 1 and first.hist[3] == 1


def test_flush_writes_rows_and_restores_on_failure(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    run_migrations(settings.effective_database_url)
    engine = make_engine(settings.effective_database_url)
    factory = make_session_factory(engine)
    with factory() as s:
        s.add(Tenant(slug="acme", name="Acme"))
        s.commit()
        tid = s.scalars(select(Tenant.id)).one()
    c = MetricsCollector()
    c.record(_rec(tenant_id=tid))

    def broken() -> object:
        raise RuntimeError("database down")

    assert c.flush(broken) == 0  # type: ignore[arg-type]
    assert len(c.drain()) == 1  # kept for the next attempt (put back, then drained here)
    c.record(_rec(tenant_id=tid, at=1_000.0))
    c.record(_rec(tenant_id=tid, at=time.time()))
    c.record(_rec(tenant_id=999_999))  # tenant deleted meanwhile: dropped, not retried forever
    assert c.flush(factory, retention_days=1) == 2
    assert c.drain() == {}
    with factory() as s:
        rows = s.scalars(select(AnalyticsBucket)).all()
    assert [r.requests for r in rows] == [1]  # the 1970 row was purged by retention
    engine.dispose()


def test_prometheus_text() -> None:
    c = MetricsCollector()
    c.record(_rec(latency_ms=3, bytes_in=5))
    c.record(_rec(latency_ms=700, tenant_slug='we"ird\\', status=503))
    c.record_unmatched()
    text = c.prometheus_text()
    assert (
        'apiedge_gateway_requests_total{tenant="acme",api_id="3",method="GET",status="200"} 1'
        in text
    )
    assert 'tenant="we\\"ird\\\\"' in text  # label values escaped
    assert 'le="0.005"} 1' in text
    assert (
        'apiedge_gateway_request_duration_seconds_bucket{tenant="acme",api_id="3",le="+Inf"} 1'
        in text
    )
    assert 'apiedge_gateway_request_bytes_total{tenant="acme",api_id="3"} 5' in text
    assert "apiedge_gateway_unmatched_requests_total 1" in text
    assert text.endswith("\n")
    for line in text.splitlines():
        assert line.startswith(("# HELP ", "# TYPE ", "apiedge_"))


def test_choose_step_and_fold() -> None:
    assert choose_step(0, 3600) == 60
    assert choose_step(0, 6 * 3600) == 300
    assert choose_step(0, 7 * 86400) == 10800
    assert choose_step(0, 31 * 86400) == 43200
    a, b = Stats(requests=1), Stats(requests=2, server_errors=1)
    folded = fold([((60, "x"), a), ((120, "x"), b), ((300, "x"), Stats(requests=4))], 300)
    assert list(folded) == [(0, "x"), (300, "x")]
    assert folded[(0, "x")].requests == 3 and folded[(0, "x")].error_rate == pytest.approx(1 / 3)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=HYPERLINK(1)", "'=HYPERLINK(1)"),
        ("+1", "'+1"),
        ("-1", "'-1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        ("/orders/{id}", "/orders/{id}"),
        (None, ""),
        (42, "42"),
    ],
)
def test_csv_cells_cannot_become_formulas(value: object, expected: str) -> None:
    assert csv_cell(value) == expected


def test_metrics_token_setting() -> None:
    with pytest.raises(ValidationError):
        Settings(metrics_token="short")
    assert Settings(metrics_token="").metrics_token is None
    token = Settings(metrics_token="x" * 16).metrics_token
    assert token is not None and token.get_secret_value() == "x" * 16
