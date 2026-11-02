# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/tenants/{tenant_id}/inspector``: the packet inspector (T-012, ADR 0010).

| Route | Permission (tenant-wide or scoped to the product) |
|---|---|
| ``GET .../inspector/sessions`` | ``inspector:view`` |
| ``POST .../inspector/sessions`` | ``inspector:capture``; audited |
| ``POST .../inspector/sessions/{id}/stop`` | ``inspector:capture``; audited |
| ``DELETE .../inspector/sessions/{id}`` | ``inspector:capture``; audited |
| ``GET .../inspector/sessions/{id}/har`` | ``inspector:view`` (+ ``inspector:unmask`` for
  ``unmasked=true``); audited |
| ``GET .../inspector/exchanges`` | ``inspector:view`` |
| ``GET .../inspector/exchanges/stream`` | ``inspector:view`` (Server-Sent Events) |
| ``GET .../inspector/exchanges/{id}`` | ``inspector:view`` (+ ``inspector:unmask`` for
  ``unmasked=true``; audited) |
| ``POST .../inspector/exchanges/{id}/replay`` | ``inspector:capture`` (+ ``inspector:unmask`` to
  see the answer unmasked); audited |

Every query runs on a tenant-bound session and is limited to the products the caller holds the
permission for; sessions and exchanges of other products and tenants answer 404. Captured data
leaves the server masked unless ``unmasked=true`` is asked for and allowed (audited).
Replays go to the API's current upstream through the SSRF-guarded client, never to a URL taken
from the request.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal
from urllib.parse import quote

import anyio
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import Select, delete, func, select
from sqlalchemy.orm import Session

from apiedge.admin.deps import TenantCaller, deny, not_found, require_any
from apiedge.admin.schemas import In
from apiedge.config import Settings
from apiedge.db.models import Api, CapturedExchange, CaptureSession
from apiedge.db.tenancy import bind_tenant
from apiedge.gateway.transport import build_client
from apiedge.inspector.har import entry, har
from apiedge.inspector.masking import Masker
from apiedge.inspector.recorder import aware
from apiedge.inspector.store import decode_body, encode_body, unseal
from apiedge.security.audit import audit
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.ssrf import SsrfError, check_url_async

router = APIRouter(prefix="/tenants/{tenant_id}/inspector", tags=["inspector"])
log = logging.getLogger("apiedge.inspector")

VIEW, CAPTURE, UNMASK = "inspector:view", "inspector:capture", "inspector:unmask"
MAX_PAGE = 200
MAX_HAR_ENTRIES = 1000
STREAM_POLL_SECONDS = 1.0
STREAM_HEARTBEAT_SECONDS = 15.0
MAX_STREAM_SECONDS = 300
_REPLAY_DROP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "x-request-id",
    }
)

FieldName = Annotated[
    str, StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.\-]+$")
]


# ------------------------------------------------------------------------------- schemas


class CaptureIn(In):
    api_id: int = Field(ge=1)
    route: Annotated[str, StringConstraints(min_length=1, max_length=500)] | None = None
    consumer: Annotated[str, StringConstraints(max_length=128)] | None = None
    duration_minutes: int = Field(default=15, ge=1, le=1440)
    max_exchanges: int = Field(default=200, ge=1, le=100_000)
    max_body_bytes: int = Field(default=16 * 1024, ge=0, le=1024 * 1024)
    mask_fields: list[FieldName] = Field(default_factory=list, max_length=50)


class CaptureOut(BaseModel):
    id: int
    product_id: int
    api_id: int
    api_name: str | None
    route: str | None
    consumer: str | None
    max_exchanges: int
    max_body_bytes: int
    mask_fields: list[str]
    created_by: str | None
    created_at: datetime
    expires_at: datetime
    stopped_at: datetime | None
    state: Literal["active", "stopped", "expired"]
    captured: int
    stored: int


class ExchangeOut(BaseModel):
    id: int
    session_id: int
    product_id: int
    api_id: int
    request_id: str
    started_at: datetime
    method: str
    path: str
    route: str
    status: int
    consumer: str
    duration_ms: float
    upstream: str


class ExchangeDetailOut(ExchangeOut):
    masked: bool
    exchange: dict[str, Any]


class ReplayOut(BaseModel):
    masked: bool
    url: str
    status: int | None
    error: str | None
    duration_ms: float
    headers: list[list[str]]
    body: dict[str, Any]


# ------------------------------------------------------------------------------- helpers


def _box(request: Request) -> SecretBox:
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="packet capture needs secrets encryption (APIEDGE_SECRET_KEY or the key file)",
        )
    return box


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _state(row: CaptureSession, now: datetime) -> Literal["active", "stopped", "expired"]:
    if row.stopped_at is not None:
        return "stopped"
    return "active" if aware(row.expires_at) > now else "expired"


def _fields(row: CaptureSession) -> list[str]:
    try:
        value = json.loads(row.mask_fields or "[]")
    except ValueError:
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def _visible(caller: TenantCaller, permission: str) -> frozenset[int] | None:
    return caller.principal.product_ids_with(permission, caller.tenant_id)


def _limit_products(stmt: Select[Any], column: Any, visible: frozenset[int] | None) -> Any:
    return stmt if visible is None else stmt.where(column.in_(visible or {-1}))


def _session_row(caller: TenantCaller, session_id: int, permission: str) -> CaptureSession:
    row = caller.session.get(CaptureSession, session_id)
    tid = caller.tenant_id
    if row is None or row.tenant_id != tid or not caller.principal.has(VIEW, tid, row.product_id):
        raise not_found("Capture session not found")
    if not caller.principal.has(permission, tid, row.product_id):
        raise deny(caller, permission, tid)
    return row


def _capture_out(caller: TenantCaller, rows: list[CaptureSession]) -> list[CaptureOut]:
    s = caller.session
    api_ids = {r.api_id for r in rows}
    names = (
        {
            i: f"{n} {v}"
            for i, n, v in s.execute(
                select(Api.id, Api.name, Api.version).where(Api.id.in_(api_ids))
            )
        }
        if api_ids
        else {}
    )
    stored: dict[int, int] = {}
    if rows:
        stored = {
            int(sid): int(n)
            for sid, n in s.execute(
                select(CapturedExchange.session_id, func.count())
                .where(CapturedExchange.session_id.in_([r.id for r in rows]))
                .group_by(CapturedExchange.session_id)
            )
        }
    now = datetime.now(timezone.utc)
    return [
        CaptureOut(
            id=r.id,
            product_id=r.product_id,
            api_id=r.api_id,
            api_name=names.get(r.api_id),
            route=r.route,
            consumer=r.consumer,
            max_exchanges=r.max_exchanges,
            max_body_bytes=r.max_body_bytes,
            mask_fields=_fields(r),
            created_by=r.created_by_name,
            created_at=aware(r.created_at),
            expires_at=aware(r.expires_at),
            stopped_at=aware(r.stopped_at) if r.stopped_at else None,
            state=_state(r, now),
            captured=r.captured,
            stored=stored.get(r.id, 0),
        )
        for r in rows
    ]


def _summary(row: CapturedExchange) -> ExchangeOut:
    return ExchangeOut(
        id=row.id,
        session_id=row.session_id,
        product_id=row.product_id,
        api_id=row.api_id,
        request_id=row.request_id,
        started_at=aware(row.started_at),
        method=row.method,
        path=row.path,
        route=row.route,
        status=row.status,
        consumer=row.consumer,
        duration_ms=row.duration_ms,
        upstream=row.upstream,
    )


def _masker(request: Request, row: CaptureSession) -> Masker:
    return Masker([*_settings(request).inspector_mask_fields, *_fields(row)])


def _unseal(box: SecretBox, row: CapturedExchange) -> dict[str, Any]:
    try:
        return unseal(box, row.tenant_id, row.session_id, row.data)
    except (CryptoError, ValueError) as exc:
        log.warning("captured exchange %s could not be decrypted", row.id)
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="the captured exchange cannot be decrypted"
        ) from exc


def _check_unmask(caller: TenantCaller, product_id: int) -> None:
    if not caller.principal.has(UNMASK, caller.tenant_id, product_id):
        raise deny(caller, UNMASK, caller.tenant_id)


class _Filters:
    def __init__(
        self,
        session_id: Annotated[int | None, Query(ge=1)] = None,
        api_id: Annotated[int | None, Query(ge=1)] = None,
        method: Annotated[str | None, Query(max_length=10, pattern=r"^[A-Za-z]+$")] = None,
        status_code: Annotated[int | None, Query(alias="status", ge=100, le=599)] = None,
        status_class: Annotated[int | None, Query(ge=1, le=5)] = None,
        path: Annotated[str | None, Query(max_length=200)] = None,
        consumer: Annotated[str | None, Query(max_length=128)] = None,
    ) -> None:
        self.session_id = session_id
        self.api_id = api_id
        self.method = method.upper() if method else None
        self.status = status_code
        self.status_class = status_class
        self.path = path
        self.consumer = consumer

    def apply(self, stmt: Select[Any]) -> Select[Any]:
        e = CapturedExchange
        if self.session_id is not None:
            stmt = stmt.where(e.session_id == self.session_id)
        if self.api_id is not None:
            stmt = stmt.where(e.api_id == self.api_id)
        if self.method:
            stmt = stmt.where(e.method == self.method)
        if self.status is not None:
            stmt = stmt.where(e.status == self.status)
        if self.status_class is not None:
            low = self.status_class * 100
            stmt = stmt.where(e.status >= low, e.status < low + 100)
        if self.path:
            escaped = self.path.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(e.path.like(f"%{escaped}%", escape="\\"))
        if self.consumer is not None:
            stmt = stmt.where(e.consumer == self.consumer)
        return stmt


# ------------------------------------------------------------------------------- sessions


@router.get("/sessions", response_model=list[CaptureOut], summary="List capture sessions")
def list_sessions(
    caller: Annotated[TenantCaller, Depends(require_any(VIEW))],
) -> list[CaptureOut]:
    stmt = select(CaptureSession).order_by(CaptureSession.id.desc()).limit(500)
    stmt = _limit_products(stmt, CaptureSession.product_id, _visible(caller, VIEW))
    return _capture_out(caller, list(caller.session.scalars(stmt)))


@router.post(
    "/sessions",
    response_model=CaptureOut,
    status_code=status.HTTP_201_CREATED,
    summary="Start capturing an API's traffic",
)
def start_session(
    body: CaptureIn,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any(CAPTURE))],
) -> CaptureOut:
    _box(request)
    settings = _settings(request)
    tid = caller.tenant_id
    api = caller.session.get(Api, body.api_id)
    if api is None or api.tenant_id != tid or not caller.principal.has(VIEW, tid, api.product_id):
        raise not_found("API not found")
    if not caller.principal.has(CAPTURE, tid, api.product_id):
        raise deny(caller, CAPTURE, tid)
    errors: list[str] = []
    if body.duration_minutes > settings.inspector_max_duration_minutes:
        errors.append(f"duration_minutes: at most {settings.inspector_max_duration_minutes}")
    if body.max_exchanges > settings.inspector_max_exchanges:
        errors.append(f"max_exchanges: at most {settings.inspector_max_exchanges}")
    if body.max_body_bytes > settings.inspector_max_body_bytes:
        errors.append(f"max_body_bytes: at most {settings.inspector_max_body_bytes}")
    if body.route is not None and body.route not in {r.path for r in api.routes}:
        errors.append("route: not a route of this API")
    if errors:
        raise HTTPException(422, detail=errors)
    now = datetime.now(timezone.utc)
    active = [
        r
        for r in caller.session.scalars(
            select(CaptureSession).where(CaptureSession.stopped_at.is_(None))
        )
        if aware(r.expires_at) > now
    ]
    if len(active) >= settings.inspector_max_active_sessions:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"at most {settings.inspector_max_active_sessions} active capture sessions "
            "per tenant: stop one first",
        )
    row = CaptureSession(
        tenant_id=tid,
        product_id=api.product_id,
        api_id=api.id,
        route=body.route,
        consumer=body.consumer,
        max_exchanges=body.max_exchanges,
        max_body_bytes=body.max_body_bytes,
        mask_fields=json.dumps(sorted({f.lower() for f in body.mask_fields})),
        created_by=caller.id,
        created_by_name=caller.username,
        created_at=now,
        expires_at=now + timedelta(minutes=body.duration_minutes),
        captured=0,
    )
    caller.session.add(row)
    caller.session.flush()
    audit(
        caller.session,
        "inspector.capture.start",
        tenant_id=tid,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="capture_session",
        resource_id=row.id,
        client_ip=caller.ip,
        details={
            "api_id": api.id,
            "route": body.route,
            "consumer": body.consumer,
            "duration_minutes": body.duration_minutes,
            "max_exchanges": body.max_exchanges,
            "max_body_bytes": body.max_body_bytes,
        },
    )
    caller.session.commit()
    return _capture_out(caller, [row])[0]


@router.post("/sessions/{session_id}/stop", response_model=CaptureOut, summary="Stop a capture")
def stop_session(
    session_id: int,
    caller: Annotated[TenantCaller, Depends(require_any(CAPTURE))],
) -> CaptureOut:
    row = _session_row(caller, session_id, CAPTURE)
    if row.stopped_at is None:
        row.stopped_at = min(datetime.now(timezone.utc), aware(row.expires_at))
        audit(
            caller.session,
            "inspector.capture.stop",
            tenant_id=caller.tenant_id,
            actor_id=caller.id,
            actor_username=caller.username,
            resource_type="capture_session",
            resource_id=row.id,
            client_ip=caller.ip,
        )
        caller.session.commit()
    return _capture_out(caller, [row])[0]


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a capture and its exchanges",
)
def delete_session(
    session_id: int,
    caller: Annotated[TenantCaller, Depends(require_any(CAPTURE))],
) -> Response:
    row = _session_row(caller, session_id, CAPTURE)
    caller.session.execute(delete(CapturedExchange).where(CapturedExchange.session_id == row.id))
    caller.session.delete(row)
    audit(
        caller.session,
        "inspector.capture.delete",
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="capture_session",
        resource_id=session_id,
        client_ip=caller.ip,
    )
    caller.session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/sessions/{session_id}/har", summary="Export a capture as HAR 1.2")
def export_har(
    session_id: int,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any(VIEW))],
    unmasked: bool = False,
) -> Response:
    row = _session_row(caller, session_id, VIEW)
    if unmasked:
        _check_unmask(caller, row.product_id)
    box = _box(request)
    stmt = (
        select(CapturedExchange)
        .where(CapturedExchange.session_id == row.id)
        .order_by(CapturedExchange.id.desc())
        .limit(MAX_HAR_ENTRIES)
    )
    masker = _masker(request, row)
    entries = []
    for ex in reversed(list(caller.session.scalars(stmt))):
        try:
            data = unseal(box, ex.tenant_id, ex.session_id, ex.data)
        except (CryptoError, ValueError):
            continue
        entries.append(entry(data if unmasked else masker.exchange(data), ex.request_id))
    audit(
        caller.session,
        "inspector.har.export",
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="capture_session",
        resource_id=row.id,
        client_ip=caller.ip,
        details={"unmasked": unmasked, "entries": len(entries)},
    )
    caller.session.commit()
    return Response(
        json.dumps(har(entries), ensure_ascii=False),
        media_type="application/json",
        headers={
            "content-disposition": f'attachment; filename="apiedge-capture-{row.id}.har"',
            "cache-control": "no-store",
        },
    )


# ------------------------------------------------------------------------------- exchanges


@router.get("/exchanges", response_model=list[ExchangeOut], summary="List captured exchanges")
def list_exchanges(
    caller: Annotated[TenantCaller, Depends(require_any(VIEW))],
    filters: Annotated[_Filters, Depends()],
    before_id: Annotated[int | None, Query(ge=1)] = None,
    after_id: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 50,
) -> list[ExchangeOut]:
    stmt = filters.apply(select(CapturedExchange))
    stmt = _limit_products(stmt, CapturedExchange.product_id, _visible(caller, VIEW))
    if before_id is not None:
        stmt = stmt.where(CapturedExchange.id < before_id)
    if after_id is not None:
        stmt = stmt.where(CapturedExchange.id > after_id)
    stmt = stmt.order_by(CapturedExchange.id.desc()).limit(limit)
    return [_summary(r) for r in caller.session.scalars(stmt)]


def _poll(
    request: Request,
    tenant_id: int,
    visible: frozenset[int] | None,
    filters: _Filters,
    after: int,
) -> list[ExchangeOut]:
    factory = request.app.state.session_factory
    session: Session
    with factory() as session:
        bind_tenant(session, tenant_id)
        stmt = filters.apply(select(CapturedExchange).where(CapturedExchange.id > after))
        stmt = _limit_products(stmt, CapturedExchange.product_id, visible)
        stmt = stmt.order_by(CapturedExchange.id.asc()).limit(MAX_PAGE)
        return [_summary(r) for r in session.scalars(stmt)]


@router.get(
    "/exchanges/stream",
    summary="Live view: new captured exchanges as Server-Sent Events",
    response_class=StreamingResponse,
)
async def stream_exchanges(
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any(VIEW))],
    filters: Annotated[_Filters, Depends()],
    after_id: Annotated[int, Query(ge=0)] = 0,
    timeout: Annotated[int, Query(ge=1, le=MAX_STREAM_SECONDS)] = MAX_STREAM_SECONDS,
) -> StreamingResponse:
    """Sends each new exchange summary as an ``exchange`` event (``id`` = exchange id).

    The stream ends after ``timeout`` seconds (at most 5 minutes) so permissions are checked
    again on reconnect; resume with ``after_id`` (or the ``Last-Event-ID`` header).
    """
    tenant_id = caller.tenant_id
    visible = _visible(caller, VIEW)
    last_event = request.headers.get("last-event-id", "")
    if last_event.isdigit():
        after_id = max(after_id, int(last_event))
    caller.session.close()  # the stream polls with its own short-lived sessions

    async def events() -> AsyncIterator[bytes]:
        after = after_id
        deadline = time.monotonic() + timeout
        last_send = time.monotonic()
        yield b"retry: 2000\n\n"
        while time.monotonic() < deadline:
            if await request.is_disconnected():
                return
            rows = await anyio.to_thread.run_sync(
                _poll, request, tenant_id, visible, filters, after
            )
            for row in rows:
                after = row.id
                payload = row.model_dump_json()
                yield f"id: {row.id}\nevent: exchange\ndata: {payload}\n\n".encode()
                last_send = time.monotonic()
            if time.monotonic() - last_send >= STREAM_HEARTBEAT_SECONDS:
                yield b": keep-alive\n\n"
                last_send = time.monotonic()
            await asyncio.sleep(min(STREAM_POLL_SECONDS, max(deadline - time.monotonic(), 0)))
        yield b"event: end\ndata: {}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"cache-control": "no-store", "x-accel-buffering": "no"},
    )


def _exchange(caller: TenantCaller, exchange_id: int) -> tuple[CapturedExchange, CaptureSession]:
    row = caller.session.get(CapturedExchange, exchange_id)
    tid = caller.tenant_id
    if row is None or row.tenant_id != tid or not caller.principal.has(VIEW, tid, row.product_id):
        raise not_found("Exchange not found")
    capture = caller.session.get(CaptureSession, row.session_id)
    if capture is None:
        raise not_found("Exchange not found")
    return row, capture


@router.get(
    "/exchanges/{exchange_id}",
    response_model=ExchangeDetailOut,
    summary="A captured exchange (masked unless unmasked=true)",
)
def get_exchange(
    exchange_id: int,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any(VIEW))],
    unmasked: bool = False,
) -> ExchangeDetailOut:
    row, capture = _exchange(caller, exchange_id)
    if unmasked:
        _check_unmask(caller, row.product_id)
    data = _unseal(_box(request), row)
    if unmasked:
        audit(
            caller.session,
            "inspector.exchange.unmask",
            tenant_id=caller.tenant_id,
            actor_id=caller.id,
            actor_username=caller.username,
            resource_type="captured_exchange",
            resource_id=row.id,
            client_ip=caller.ip,
            details={"session_id": row.session_id, "request_id": row.request_id},
        )
        caller.session.commit()
    else:
        data = _masker(request, capture).exchange(data)
    return ExchangeDetailOut(**_summary(row).model_dump(), masked=not unmasked, exchange=data)


@router.post(
    "/exchanges/{exchange_id}/replay",
    response_model=ReplayOut,
    summary="Send a captured request to the API's upstream again",
)
async def replay_exchange(
    exchange_id: int,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any(CAPTURE))],
    unmasked: bool = False,
) -> ReplayOut:
    row, capture = _exchange(caller, exchange_id)
    tid = caller.tenant_id
    if not caller.principal.has(CAPTURE, tid, row.product_id):
        raise deny(caller, CAPTURE, tid)
    if unmasked:
        _check_unmask(caller, row.product_id)
    data = _unseal(_box(request), row)
    req = data.get("request") or {}
    body_info = req.get("body") or {}
    if req.get("upstream_headers") is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="this request was answered by the gateway and never reached an upstream",
        )
    if body_info.get("truncated"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="the request body was only partly captured and cannot be replayed",
        )
    api = caller.session.get(Api, row.api_id)
    if api is None or api.tenant_id != tid or not api.upstreams:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the API no longer has an upstream")
    urls = [u.url.rstrip("/") for u in api.upstreams]
    recorded = str(data.get("upstream") or "").rstrip("/")
    base = recorded if recorded in urls else urls[0]  # only ever one of the API's upstreams
    target = base + quote(str(req.get("upstream_path") or "/"), safe="/:@!$&'()*+,;=-._~")
    if req.get("upstream_query"):
        target += "?" + str(req["upstream_query"])
    timeout = api.timeout_ms / 1000
    settings = _settings(request)
    masker = _masker(request, capture)
    audit(
        caller.session,
        "inspector.exchange.replay",
        tenant_id=tid,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="captured_exchange",
        resource_id=row.id,
        client_ip=caller.ip,
        details={"session_id": row.session_id, "unmasked": unmasked, "upstream": base},
    )
    caller.session.commit()
    shown_url = target if unmasked else masker.url(target)

    policy = settings.ssrf_policy()
    try:
        await check_url_async(target, policy)
    except SsrfError:
        return ReplayOut(
            masked=not unmasked,
            url=shown_url,
            status=None,
            error="the upstream URL is not allowed by the SSRF policy",
            duration_ms=0.0,
            headers=[],
            body=encode_body(None, 0, 0),
        )
    headers = [
        (str(k), str(v)) for k, v in req["upstream_headers"] if str(k).lower() not in _REPLAY_DROP
    ]
    headers.append(("x-request-id", uuid.uuid4().hex))
    headers.append(("x-apiedge-replay-of", row.request_id))
    content = decode_body(body_info) if body_info.get("captured") else b""
    limit = max(capture.max_body_bytes, 1024)
    resolver = getattr(request.app.state, "upstream_resolver", None)
    started = time.perf_counter()
    async with build_client(policy, settings.gateway_ca_bundle, resolver) as client:
        try:
            upstream_request = client.build_request(
                str(req.get("method") or "GET"),
                target,
                headers=headers,
                content=content or None,
                timeout=httpx.Timeout(timeout),
            )
            resp = await client.send(upstream_request, stream=True)
            try:
                chunks: list[bytes] = []
                held = 0
                total = 0
                async for chunk in resp.aiter_raw():
                    total += len(chunk)
                    if held < limit:
                        chunks.append(chunk[: limit - held])
                        held += len(chunks[-1])
            finally:
                await resp.aclose()
        except httpx.HTTPError:
            return ReplayOut(
                masked=not unmasked,
                url=shown_url,
                status=None,
                error="the upstream could not be reached or did not answer in time",
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                headers=[],
                body=encode_body(None, 0, 0),
            )
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    out_headers = [[k.decode("latin-1"), v.decode("latin-1")] for k, v in resp.headers.raw]
    body = encode_body(b"".join(chunks), total, limit)
    if not unmasked:
        out_headers = masker.headers(out_headers)
        body = masker.body(body, resp.headers.get("content-type", ""))
    return ReplayOut(
        masked=not unmasked,
        url=shown_url,
        status=resp.status_code,
        error=None,
        duration_ms=elapsed,
        headers=out_headers,
        body=body,
    )
