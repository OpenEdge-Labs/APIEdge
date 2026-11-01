# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Gateway data plane (T-007, ADR 0007): an ASGI app that proxies published APIs.

``/<tenant slug><base path><route path>`` is matched against the routing snapshot and forwarded
to one of the API's upstreams (smooth weighted round-robin) with the API's timeout. Failed calls
are retried on another upstream: connection failures for every method (nothing was sent),
timeouts and 502/503/504 answers only for idempotent methods. Hop-by-hop headers are not
forwarded, ``X-Forwarded-*`` is set, request bodies are size-limited, and the gateway's own
errors are fixed JSON documents that never contain upstream or exception details.

Every request that resolves to an API is measured (T-013): status, latency until the last
response byte, body sizes, route and method go to the shared ``MetricsCollector``, which a
background task flushes to the analytics tables.

The data plane is a separate ASGI app on its own port (``APIEDGE_GATEWAY_PORT``): it does not
use the console's cookie, CSRF or CSP middleware, and console paths cannot shadow API paths.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote

import anyio
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from apiedge.analytics.metrics import MetricsCollector, RequestRecord
from apiedge.config import Settings, get_settings
from apiedge.db.base import make_engine, make_session_factory
from apiedge.gateway.bus import ConfigBus, build_bus
from apiedge.gateway.snapshot import DEPRECATED, RETIRED, RuntimeApi, Snapshot, load_snapshot
from apiedge.gateway.transport import build_client
from apiedge.security.ssrf import AsyncResolver

log = logging.getLogger("apiedge.gateway")

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
RETRY_STATUSES = frozenset({502, 503, 504})
HOP_BY_HOP = frozenset(
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
    }
)
# Set by the gateway itself (or by httpx from the URL and body), never copied from the client.
_REQUEST_DROP = HOP_BY_HOP | {
    "host",
    "content-length",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-prefix",
    "x-request-id",
}
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PATH_SAFE = "/:@!$&'()*+,;=-._~"


class GatewayRuntime:
    """Holds the current snapshot and reloads it on change events."""

    def __init__(
        self,
        settings: Settings,
        bus: ConfigBus,
        resolver: AsyncResolver | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        self.settings = settings
        self.bus = bus
        self.metrics = metrics or MetricsCollector()
        self.snapshot = Snapshot()
        self.version = 0
        self._resolver = resolver
        self._engine = make_engine(settings.effective_database_url)
        self._factory = make_session_factory(self._engine)
        self.client: httpx.AsyncClient | None = None

    async def reload(self) -> None:
        try:
            snapshot = await anyio.to_thread.run_sync(load_snapshot, self._factory)
        except Exception:
            log.exception("gateway configuration reload failed; keeping the previous one")
            return
        self.snapshot = snapshot
        self.version += 1

    async def _reloader(self, changed: asyncio.Event) -> None:
        interval = self.settings.gateway_reload_interval_seconds or None
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(changed.wait(), timeout=interval)
            changed.clear()
            await self.reload()

    async def flush_metrics(self) -> int:
        """Write pending analytics aggregates (database I/O in a worker thread)."""
        rows: int = await anyio.to_thread.run_sync(
            self.metrics.flush, self._factory, self.settings.analytics_retention_days
        )
        return rows

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(self.settings.analytics_flush_interval_seconds)
            await self.flush_metrics()

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()
        changed = asyncio.Event()

        def on_change() -> None:  # called from admin worker threads too
            with contextlib.suppress(RuntimeError):  # loop already closed
                loop.call_soon_threadsafe(changed.set)

        unsubscribe = self.bus.subscribe(on_change)
        self.client = build_client(
            self.settings.ssrf_policy(), self.settings.gateway_ca_bundle, self._resolver
        )
        await self.reload()
        tasks = [
            asyncio.create_task(self._reloader(changed)),
            asyncio.create_task(self.bus.run_listener()),
            asyncio.create_task(self._flusher()),
        ]
        try:
            yield
        finally:
            unsubscribe()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.flush_metrics()  # keep the last seconds of traffic
            await self.client.aclose()
            self._engine.dispose()


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        {"error": code, "message": message, "request_id": request_id},
        status_code=status,
        headers={
            "x-request-id": request_id,
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
    )


def _connection_tokens(headers: list[tuple[bytes, bytes]]) -> set[str]:
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            tokens |= {t.strip().lower() for t in value.decode("latin-1").split(",") if t.strip()}
    return tokens


def _forward_headers(request: Request, request_id: str, prefix: str) -> list[tuple[bytes, bytes]]:
    raw = request.scope["headers"]
    drop = _REQUEST_DROP | _connection_tokens(raw)
    out = [(k, v) for k, v in raw if k.decode("latin-1").lower() not in drop]
    client_ip = request.client.host if request.client else ""
    prior = ", ".join(request.headers.getlist("x-forwarded-for"))
    if client_ip:
        out = [(k, v) for k, v in out if k.lower() != b"x-forwarded-for"]
        chain = f"{prior}, {client_ip}" if prior else client_ip
        out.append((b"x-forwarded-for", chain.encode("latin-1")))
    host = request.headers.get("host")
    if host:
        out.append((b"x-forwarded-host", host.encode("latin-1")))
    out.append((b"x-forwarded-proto", request.url.scheme.encode("latin-1")))
    out.append((b"x-forwarded-prefix", quote(prefix, safe=_PATH_SAFE).encode("latin-1")))
    out.append((b"x-request-id", request_id.encode("latin-1")))
    return out


def _response_headers(
    upstream: httpx.Response, request_id: str, api: RuntimeApi
) -> list[tuple[bytes, bytes]]:
    raw = upstream.headers.raw
    drop = HOP_BY_HOP | _connection_tokens(raw) | {"x-request-id"}
    out = [(k, v) for k, v in raw if k.decode("latin-1").lower() not in drop]
    out.append((b"x-request-id", request_id.encode("latin-1")))
    if api.state == DEPRECATED:
        out.append((b"deprecation", b"true"))
    return out


class _Meter:
    """Measures one request to an API and records it once answered."""

    def __init__(self, metrics: MetricsCollector, api: RuntimeApi, method: str) -> None:
        self.metrics = metrics
        self.api = api
        self.method = method
        self.route = ""
        self.bytes_in = 0
        self.at = time.time()
        self.started = time.perf_counter()

    def finish(self, status: int, bytes_out: int) -> None:
        api = self.api
        self.metrics.record(
            RequestRecord(
                tenant_id=api.tenant_id,
                tenant_slug=api.tenant_slug,
                product_id=api.product_id,
                api_id=api.api_id,
                route=self.route,
                method=self.method,
                status=status,
                latency_ms=(time.perf_counter() - self.started) * 1000,
                bytes_in=self.bytes_in,
                bytes_out=bytes_out,
                at=self.at,
            )
        )

    def done(self, response: Response) -> Response:
        self.finish(response.status_code, len(response.body))
        return response


class BodyTooLargeError(Exception):
    pass


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise BodyTooLargeError
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise BodyTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


async def proxy(request: Request) -> Response:
    runtime: GatewayRuntime = request.app.state.runtime
    supplied = request.headers.get("x-request-id", "")
    request_id = supplied if _REQUEST_ID.match(supplied) else uuid.uuid4().hex

    path = request.url.path
    segments = path.split("/")
    if any(seg in (".", "..") for seg in segments) or "\x00" in path:
        return _error(400, "bad_request", "Invalid request path.", request_id)
    slug = segments[1] if len(segments) > 1 else ""
    rest = "/" + "/".join(segments[2:])
    found = runtime.snapshot.resolve(slug, rest)
    if found is None:
        runtime.metrics.record_unmatched()
        return _error(404, "not_found", "No API matches this path.", request_id)
    api, remainder = found
    method = request.method.upper()
    meter = _Meter(runtime.metrics, api, method)
    if api.state == RETIRED:
        return meter.done(_error(410, "api_retired", "This API has been retired.", request_id))

    rule, allowed = api.match(method, remainder)
    if rule is None:
        if not allowed:
            return meter.done(_error(404, "not_found", "No API matches this path.", request_id))
        resp = _error(405, "method_not_allowed", "Method not allowed.", request_id)
        resp.headers["allow"] = ", ".join(sorted(allowed))
        return meter.done(resp)
    meter.route = rule.path

    try:
        body = await _read_body(request, runtime.settings.gateway_max_request_body_bytes)
    except BodyTooLargeError:
        return meter.done(
            _error(413, "payload_too_large", "Request body is too large.", request_id)
        )
    meter.bytes_in = len(body)

    prefix = f"/{slug}{api.base_path}"
    headers = _forward_headers(request, request_id, prefix)
    target = quote(remainder, safe=_PATH_SAFE)
    query = request.scope.get("query_string", b"").decode("latin-1")
    return await _send(runtime, api, method, target, query, headers, body, request_id, meter)


async def _send(
    runtime: GatewayRuntime,
    api: RuntimeApi,
    method: str,
    target: str,
    query: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
    request_id: str,
    meter: _Meter,
) -> Response:
    assert runtime.client is not None  # noqa: S101  # nosec B101 - set during lifespan
    idempotent = method in IDEMPOTENT
    attempts = 1 + runtime.settings.gateway_retries
    tried: set[int] = set()
    failure = (502, "bad_gateway", "The upstream service could not be reached.")
    for attempt in range(attempts):
        last = attempt == attempts - 1
        index = api.balancer.pick(frozenset(tried))
        tried.add(index)
        base = api.upstreams[index].url
        url = base + target
        if query:
            url += "?" + query
        upstream_request = httpx.Request(
            method,
            url,
            headers=headers,
            content=body or None,
            extensions={"timeout": httpx.Timeout(api.timeout_seconds).as_dict()},
        )
        try:
            upstream = await runtime.client.send(upstream_request, stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            # Nothing reached the upstream: safe to try again for every method.
            log.warning("upstream connect failed (api %s, attempt %s)", api.api_id, attempt + 1)
            failure = (502, "bad_gateway", "The upstream service could not be reached.")
            continue
        except httpx.TimeoutException:
            log.warning("upstream timed out (api %s, attempt %s)", api.api_id, attempt + 1)
            failure = (504, "gateway_timeout", "The upstream service did not answer in time.")
            if idempotent:
                continue
            break
        except httpx.HTTPError:
            log.warning("upstream call failed (api %s, attempt %s)", api.api_id, attempt + 1)
            failure = (502, "bad_gateway", "The upstream service failed to answer.")
            if idempotent:
                continue
            break
        if upstream.status_code in RETRY_STATUSES and idempotent and not last:
            await upstream.aclose()
            continue
        return _stream(upstream, request_id, api, meter)
    status, code, message = failure
    return meter.done(_error(status, code, message, request_id))


def _stream(upstream: httpx.Response, request_id: str, api: RuntimeApi, meter: _Meter) -> Response:
    async def body() -> AsyncIterator[bytes]:
        sent = 0
        try:
            async for chunk in upstream.aiter_raw():
                sent += len(chunk)
                yield chunk
        except httpx.HTTPError:
            log.warning("upstream response interrupted (api %s)", api.api_id)
        finally:
            await upstream.aclose()
            meter.finish(upstream.status_code, sent)

    response = StreamingResponse(body(), status_code=upstream.status_code)
    response.raw_headers = _response_headers(upstream, request_id, api)
    return response


async def healthz(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


async def readyz(request: Request) -> Response:
    runtime: GatewayRuntime = request.app.state.runtime
    if not runtime.snapshot.loaded:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return JSONResponse({"status": "ok"})


def create_gateway_app(
    settings: Settings | None = None,
    bus: ConfigBus | None = None,
    resolver: AsyncResolver | None = None,
    metrics: MetricsCollector | None = None,
) -> Starlette:
    """The gateway ASGI app. Share ``bus`` with :func:`apiedge.app.create_app` in one process."""
    settings = settings or get_settings()
    redis_url = settings.redis_url.get_secret_value() if settings.redis_url else None
    runtime = GatewayRuntime(settings, bus or build_bus(redis_url), resolver, metrics)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with runtime.running():
            yield

    app = Starlette(
        routes=[
            # Tenant slugs cannot start with "-", so these never shadow an API.
            Route("/-/healthz", healthz, methods=["GET"]),
            Route("/-/readyz", readyz, methods=["GET"]),
            Route("/{path:path}", proxy, methods=METHODS),
        ],
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    return app
