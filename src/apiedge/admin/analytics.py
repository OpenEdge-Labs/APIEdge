# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/tenants/{tenant_id}/analytics``: gateway traffic analytics (T-013, ADR 0008).

| Route | Permission |
|---|---|
| ``GET .../analytics/summary`` | ``analytics:view`` (tenant-wide, or per product) |
| ``GET .../analytics/export.csv`` | ``analytics:view`` (tenant-wide, or per product); audited |

The session is bound to the tenant, so only the tenant's rows are read. A caller holding
``analytics:view`` only for some products sees only those products' traffic; a ``product_id``
filter outside that set yields no data (nothing is disclosed).
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select

from apiedge.admin.deps import TenantCaller, require_any
from apiedge.analytics.query import Filters, export_rows, summarize
from apiedge.db.models import Api, Product
from apiedge.security.audit import audit

router = APIRouter(prefix="/tenants/{tenant_id}/analytics", tags=["analytics"])

MAX_RANGE = timedelta(days=31)
DEFAULT_RANGE = timedelta(hours=1)
MAX_EXPORT_SOURCE_ROWS = 200_000
PERMISSION = "analytics:view"
UNPROCESSABLE = 422  # named constant differs across Starlette versions


class StatsOut(BaseModel):
    requests: int
    errors: int
    error_rate: float
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    latency_p99_ms: float | None


class TotalsOut(StatsOut):
    client_errors: int
    server_errors: int
    latency_avg_ms: float | None
    latency_max_ms: float | None
    bytes_in: int
    bytes_out: int


class PointOut(StatsOut):
    t: int  # bucket start, epoch seconds (UTC)


class StatusOut(BaseModel):
    status: int
    requests: int


class TopApiOut(StatsOut):
    api_id: int
    product_id: int
    name: str | None  # None when the API has been deleted since


class TopConsumerOut(StatsOut):
    consumer: str  # "" = anonymous (no consumer identified)


class SummaryOut(BaseModel):
    start: datetime
    end: datetime
    step_seconds: int
    totals: TotalsOut
    series: list[PointOut]
    status_codes: list[StatusOut]
    top_apis: list[TopApiOut]
    top_consumers: list[TopConsumerOut]


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _filters(
    caller: TenantCaller,
    start: datetime | None,
    end: datetime | None,
    product_id: int | None,
    api_id: int | None,
    consumer: str | None,
) -> tuple[Filters, datetime, datetime]:
    end_ = _utc(end) if end else datetime.now(timezone.utc)
    start_ = _utc(start) if start else end_ - DEFAULT_RANGE
    if start_ >= end_:
        raise HTTPException(UNPROCESSABLE, detail="start must be before end")
    if end_ - start_ > MAX_RANGE:
        raise HTTPException(UNPROCESSABLE, detail="the time range may span at most 31 days")
    visible = caller.principal.product_ids_with(PERMISSION, caller.tenant_id)
    products: frozenset[int] | None = visible
    if product_id is not None:
        products = (
            frozenset({product_id}) & visible if visible is not None else frozenset({product_id})
        )
    filters = Filters(
        start=int(start_.timestamp()),
        end=int(end_.timestamp()),
        product_ids=products,
        api_id=api_id,
        consumer=consumer,
    )
    return filters, start_, end_


StartQ = Annotated[datetime | None, Query(description="Range start (ISO 8601; default end-1h)")]
EndQ = Annotated[datetime | None, Query(description="Range end (ISO 8601; default now)")]
ProductQ = Annotated[int | None, Query(ge=1)]
ApiQ = Annotated[int | None, Query(ge=1)]
ConsumerQ = Annotated[str | None, Query(max_length=128, description="'' = anonymous traffic")]


def _api_names(caller: TenantCaller, ids: list[int]) -> dict[int, str]:
    if not ids:
        return {}
    rows = caller.session.execute(select(Api.id, Api.name, Api.version).where(Api.id.in_(ids)))
    return {int(i): f"{n} {v}" for i, n, v in rows}


@router.get("/summary", response_model=SummaryOut, summary="Traffic, latency and error summary")
def analytics_summary(
    caller: Annotated[TenantCaller, Depends(require_any(PERMISSION))],
    start: StartQ = None,
    end: EndQ = None,
    product_id: ProductQ = None,
    api_id: ApiQ = None,
    consumer: ConsumerQ = None,
) -> SummaryOut:
    filters, start_, end_ = _filters(caller, start, end, product_id, api_id, consumer)
    data: dict[str, Any] = summarize(caller.session, filters)
    names = _api_names(caller, [a["api_id"] for a in data["top_apis"]])
    for item in data["top_apis"]:
        item["name"] = names.get(item["api_id"])
    return SummaryOut(start=start_, end=end_, **data)


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """A CSV cell that spreadsheet programs will not evaluate as a formula (CSV injection)."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


EXPORT_HEADER = (
    "time_utc",
    "product_id",
    "product",
    "api_id",
    "api",
    "route",
    "method",
    "consumer",
    "status",
    "requests",
    "errors",
    "latency_avg_ms",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "latency_max_ms",
    "bytes_in",
    "bytes_out",
)


@router.get(
    "/export.csv",
    summary="Export analytics as CSV",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}}}},
)
def analytics_export(
    caller: Annotated[TenantCaller, Depends(require_any(PERMISSION))],
    start: StartQ = None,
    end: EndQ = None,
    product_id: ProductQ = None,
    api_id: ApiQ = None,
    consumer: ConsumerQ = None,
) -> Response:
    filters, start_, end_ = _filters(caller, start, end, product_id, api_id, consumer)
    result = export_rows(caller.session, filters, MAX_EXPORT_SOURCE_ROWS)
    if result is None:
        raise HTTPException(
            UNPROCESSABLE,
            detail="too much data for one export; narrow the time range or filters",
        )
    step, rows = result
    api_ids = sorted({int(key[2]) for key, _ in rows})
    names = _api_names(caller, api_ids)
    product_names = {
        int(i): str(n)
        for i, n in caller.session.execute(
            select(Product.id, Product.name).where(
                Product.id.in_(sorted({int(key[1]) for key, _ in rows}))
            )
        )
    }
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(EXPORT_HEADER)
    for (t, prod, api, route, method, consumer_, status_code), stats in rows:
        writer.writerow(
            csv_cell(v)
            for v in (
                datetime.fromtimestamp(int(t), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                prod,
                product_names.get(int(prod), ""),
                api,
                names.get(int(api), ""),
                route,
                method,
                consumer_,
                status_code,
                stats.requests,
                stats.errors,
                stats.latency_avg_ms,
                stats.p(0.5),
                stats.p(0.95),
                stats.p(0.99),
                round(stats.latency_max_ms, 3),
                stats.bytes_in,
                stats.bytes_out,
            )
        )
    audit(
        caller.session,
        "analytics.export",
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="analytics",
        client_ip=caller.ip,
        details={
            "start": start_.isoformat(),
            "end": end_.isoformat(),
            "product_id": product_id,
            "api_id": api_id,
            "consumer": consumer,
            "rows": len(rows),
            "step_seconds": step,
        },
    )
    caller.session.commit()
    stamp = start_.strftime("%Y%m%dT%H%M")
    return Response(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "content-disposition": f'attachment; filename="apiedge-analytics-{stamp}.csv"',
            "cache-control": "no-store",
        },
    )
