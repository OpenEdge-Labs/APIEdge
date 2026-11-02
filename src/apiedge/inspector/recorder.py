# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Gateway side of the packet inspector (T-012, ADR 0010).

:class:`CaptureRecorder` is registered as a gateway trace listener. For a request whose API,
route and consumer match an active capture session it returns a tap that copies the exchange
(bodies cut at the session's limit) into an in-memory queue bounded in bytes; exchanges that do
not fit are dropped and counted, never blocking traffic.

:meth:`CaptureRecorder.tick` runs in a worker thread every
``APIEDGE_INSPECTOR_POLL_INTERVAL_SECONDS``: it reloads the active sessions, writes the queued
exchanges encrypted, keeps only the newest ``max_exchanges`` per session (ring buffer) and
deletes sessions, with their exchanges, once the retention period after their end has passed.
Requests are matched against each session's expiry on the spot, so capture stops on time even
between ticks.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.models import CapturedExchange, CaptureSession
from apiedge.inspector.store import encode_body, seal
from apiedge.security.crypto import SecretBox

if TYPE_CHECKING:
    from apiedge.policies.base import GatewayResponse, RequestContext

log = logging.getLogger("apiedge.inspector")

RETENTION_CHECK_SECONDS = 60.0
_DELETE_CHUNK = 500


def aware(value: datetime) -> datetime:
    """SQLite returns naive datetimes; every stored datetime is UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def session_end(row: CaptureSession) -> datetime:
    end = aware(row.expires_at)
    if row.stopped_at is not None:
        end = min(end, aware(row.stopped_at))
    return end


@dataclass(frozen=True)
class ActiveCapture:
    id: int
    tenant_id: int
    product_id: int
    api_id: int
    route: str | None
    consumer: str | None
    expires_at: float  # epoch seconds
    max_body: int

    def matches(self, ctx: RequestContext, now: float) -> bool:
        return (
            now < self.expires_at
            and ctx.tenant_id == self.tenant_id
            and ctx.api_id == self.api_id
            and (self.route is None or self.route == ctx.route)
            and (self.consumer is None or self.consumer == ctx.consumer)
        )


@dataclass
class PendingExchange:
    capture: ActiveCapture
    request_id: str
    started_at: float
    method: str
    path: str
    route: str
    status: int
    consumer: str
    duration_ms: float
    upstream: str
    data: dict[str, Any]
    size: int  # bytes held in memory (bodies)


class _Tap:
    """Copies one exchange for the matching sessions; finished by the gateway."""

    def __init__(
        self,
        recorder: CaptureRecorder,
        captures: list[ActiveCapture],
        ctx: RequestContext,
        resp: GatewayResponse,
    ) -> None:
        self.recorder = recorder
        self.captures = captures
        self.limit = max(c.max_body for c in captures)
        self.chunks: list[bytes] = []
        self.held = 0
        self.ctx = ctx
        self.status = resp.status
        self.source = resp.source
        self.response_headers = [list(h) for h in resp.headers]
        self.trace = [t.as_dict() for t in ctx.trace]
        self.forwarded = resp.source == "upstream"
        self.upstream_headers = [list(h) for h in ctx.headers] if self.forwarded else None
        self.upstream_query = urlencode(ctx.query) if ctx.query_changed else ctx.raw_query

    def body_chunk(self, chunk: bytes) -> None:
        room = self.limit - self.held
        if room > 0:
            part = chunk[:room]
            self.chunks.append(part)
            self.held += len(part)

    def finish(self, bytes_out: int) -> None:
        ctx = self.ctx
        started = ctx.started_perf
        total_ms = max(0.0, (time.perf_counter() - started) * 1000) if started else 0.0
        response_body = b"".join(self.chunks)
        request_body = ctx.body_read
        split = urlsplit(ctx.url)
        policies_ms = round(sum(float(t["duration_ms"]) for t in self.trace), 3)
        for capture in self.captures:
            req = encode_body(request_body, len(request_body or b""), capture.max_body)
            res = encode_body(response_body, bytes_out, capture.max_body)
            data: dict[str, Any] = {
                "request": {
                    "method": ctx.method,
                    "url": ctx.url,
                    "path": split.path,
                    "query": split.query,
                    "headers": [list(h) for h in ctx.received_headers],
                    "body": req,
                    "upstream_path": ctx.path,
                    "upstream_query": self.upstream_query,
                    "upstream_headers": self.upstream_headers,
                },
                "response": {
                    "status": self.status,
                    "headers": self.response_headers,
                    "body": res,
                    "source": self.source,
                },
                "client_ip": ctx.client_ip,
                "consumer": ctx.consumer,
                "route": ctx.route,
                "upstream": ctx.upstream_url,
                "upstream_attempts": ctx.upstream_attempts,
                "timings": {
                    "total_ms": round(total_ms, 3),
                    "upstream_ms": None if ctx.upstream_ms is None else round(ctx.upstream_ms, 3),
                    "policies_ms": policies_ms,
                },
                "trace": self.trace,
                "started_at": ctx.started_at,
            }
            self.recorder.enqueue(
                PendingExchange(
                    capture=capture,
                    request_id=ctx.request_id,
                    started_at=ctx.started_at or time.time(),
                    method=ctx.method[:10],
                    path=split.path[:2048],
                    route=ctx.route[:500],
                    status=self.status,
                    consumer=ctx.consumer,
                    duration_ms=round(total_ms, 3),
                    upstream=ctx.upstream_url[:2048],
                    data=data,
                    size=len(req["text"]) + len(res["text"]) + 1024,
                )
            )


class CaptureRecorder:
    def __init__(self, queue_max_bytes: int, mask_fields: tuple[str, ...] = ()) -> None:
        self.queue_max_bytes = queue_max_bytes
        self.mask_fields = mask_fields
        self._by_api: dict[int, list[ActiveCapture]] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()  # one writer at a time (loop, shutdown, tests)
        self._pending: list[PendingExchange] = []
        self._pending_bytes = 0
        self.dropped = 0
        self._last_retention = 0.0
        self._warned_no_key = False

    # ------------------------------------------------------------------ event loop side

    def listener(self, ctx: RequestContext, resp: GatewayResponse) -> _Tap | None:
        candidates = self._by_api.get(ctx.api_id)
        if not candidates:
            return None
        now = time.time()
        matched = [c for c in candidates if c.matches(ctx, now)]
        return _Tap(self, matched, ctx, resp) if matched else None

    def enqueue(self, item: PendingExchange) -> None:
        with self._lock:
            if self._pending_bytes + item.size > self.queue_max_bytes:
                self.dropped += 1
                return
            self._pending.append(item)
            self._pending_bytes += item.size

    @property
    def active(self) -> list[ActiveCapture]:
        return [c for caps in self._by_api.values() for c in caps]

    # ------------------------------------------------------------------ worker thread side

    def tick(
        self, factory: sessionmaker[Session], box: SecretBox | None, retention_hours: int
    ) -> int:
        """Reload sessions, write queued exchanges, enforce limits. Returns rows written."""
        self.load(factory)
        written = self.flush(factory, box)
        now = time.time()
        if now - self._last_retention >= RETENTION_CHECK_SECONDS:
            self._last_retention = now
            self.purge(factory, retention_hours)
        return written

    def load(self, factory: sessionmaker[Session]) -> None:
        now = datetime.now(timezone.utc)
        by_api: dict[int, list[ActiveCapture]] = defaultdict(list)
        with factory() as s:  # platform scope: every tenant's sessions
            for row in s.scalars(select(CaptureSession).where(CaptureSession.stopped_at.is_(None))):
                expires = aware(row.expires_at)
                if expires <= now:
                    continue
                by_api[row.api_id].append(
                    ActiveCapture(
                        id=row.id,
                        tenant_id=row.tenant_id,
                        product_id=row.product_id,
                        api_id=row.api_id,
                        route=row.route,
                        consumer=row.consumer,
                        expires_at=expires.timestamp(),
                        max_body=row.max_body_bytes,
                    )
                )
        self._by_api = dict(by_api)

    def _drain(self) -> list[PendingExchange]:
        with self._lock:
            items, self._pending, self._pending_bytes = self._pending, [], 0
        return items

    def flush(self, factory: sessionmaker[Session], box: SecretBox | None) -> int:
        """Write the queued exchanges. A concurrent call waits for the write in progress, so
        on return everything enqueued before the call is committed."""
        with self._write_lock:
            return self._flush(factory, box)

    def _flush(self, factory: sessionmaker[Session], box: SecretBox | None) -> int:
        items = self._drain()
        if not items:
            return 0
        if box is None:
            if not self._warned_no_key:
                log.warning("packet capture needs the secrets master key; exchanges dropped")
                self._warned_no_key = True
            self.dropped += len(items)
            return 0
        with factory() as s:
            ids = {i.capture.id for i in items}
            sessions = {
                r.id: r for r in s.scalars(select(CaptureSession).where(CaptureSession.id.in_(ids)))
            }
            counts: dict[int, int] = defaultdict(int)
            for item in items:
                row = sessions.get(item.capture.id)
                if row is None:  # deleted meanwhile
                    continue
                s.add(
                    CapturedExchange(
                        tenant_id=row.tenant_id,
                        session_id=row.id,
                        product_id=row.product_id,
                        api_id=row.api_id,
                        request_id=item.request_id[:128],
                        started_at=datetime.fromtimestamp(item.started_at, timezone.utc),
                        method=item.method,
                        path=item.path,
                        route=item.route,
                        status=item.status,
                        consumer=item.consumer,
                        duration_ms=item.duration_ms,
                        upstream=item.upstream,
                        size=item.size,
                        data=seal(box, row.tenant_id, row.id, item.data),
                    )
                )
                counts[row.id] += 1
            s.flush()
            for sid, n in counts.items():
                s.execute(
                    update(CaptureSession)
                    .where(CaptureSession.id == sid)
                    .values(captured=CaptureSession.captured + n)
                )
                keep = sessions[sid].max_exchanges
                old = list(
                    s.scalars(
                        select(CapturedExchange.id)
                        .where(CapturedExchange.session_id == sid)
                        .order_by(CapturedExchange.id.desc())
                        .offset(keep)
                    )
                )
                for i in range(0, len(old), _DELETE_CHUNK):
                    chunk = old[i : i + _DELETE_CHUNK]
                    s.execute(delete(CapturedExchange).where(CapturedExchange.id.in_(chunk)))
            s.commit()
        return sum(counts.values())

    def purge(self, factory: sessionmaker[Session], retention_hours: int) -> int:
        """Delete sessions (and their exchanges) whose end is older than the retention."""
        cutoff = time.time() - retention_hours * 3600
        with factory() as s:
            expired = [
                r.id
                for r in s.scalars(select(CaptureSession))
                if session_end(r).timestamp() < cutoff
            ]
            for i in range(0, len(expired), _DELETE_CHUNK):
                chunk = expired[i : i + _DELETE_CHUNK]
                s.execute(delete(CapturedExchange).where(CapturedExchange.session_id.in_(chunk)))
                s.execute(delete(CaptureSession).where(CaptureSession.id.in_(chunk)))
            s.commit()
        if expired:
            log.info("packet inspector: %s expired capture sessions deleted", len(expired))
        return len(expired)
