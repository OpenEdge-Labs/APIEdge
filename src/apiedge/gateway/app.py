# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Gateway data plane (T-007, ADR 0007): an ASGI app that proxies published APIs.

``/<tenant slug><base path><route path>`` is matched against the routing snapshot and forwarded
to one of the API's upstreams (smooth weighted round-robin) with the API's timeout. Failed calls
are retried on another upstream: connection failures for every method (nothing was sent),
timeouts and 502/503/504 answers only for idempotent methods. Hop-by-hop headers are not
forwarded, ``X-Forwarded-*`` is set, request bodies are size-limited, and the gateway's own
errors are fixed JSON documents that never contain upstream or exception details.

Between matching and forwarding the API's policy pipeline runs (T-008, ADR 0009): policies may
change the request, answer it themselves (authentication failures, rate limits, mocks, cache
hits) and change the response on its way back. Every policy decision is recorded in the
request's trace, which is handed to the registered trace listeners (the packet inspector, T-012).
CORS preflights are answered by the route's CORS policy before the rest of the chain runs.

Every request that resolves to an API is measured (T-013): status, latency until the last
response byte, body sizes, route, method and consumer go to the shared ``MetricsCollector``,
which a background task flushes to the analytics tables.

The data plane is a separate ASGI app on its own port (``APIEDGE_GATEWAY_PORT``): it does not
use the console's cookie, CSRF or CSP middleware, and console paths cannot shadow API paths.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode

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
from apiedge.policies.base import (
    BodyTooLargeError,
    GatewayResponse,
    RequestContext,
    TraceEntry,
    json_error,
)
from apiedge.policies.builtin import Cors, PolicyServices
from apiedge.policies.jwt import JwksCache
from apiedge.policies.stores import Limiter, MemoryLimiter, RedisLimiter, ResponseCache
from apiedge.security.crypto import SecretBox, load_secret_box
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

TraceListener = Callable[[RequestContext, int], None]
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(text.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def client_address(peer: str, forwarded_for: Sequence[str], trusted: Sequence[IPNetwork]) -> str:
    """The client's address: the peer, unless the peer is a trusted proxy.

    Behind trusted proxies, ``X-Forwarded-For`` is read from the right and the first address
    that is not a trusted proxy is the client. Entries left of it are client-controlled and
    ignored; a malformed entry stops the walk at the last address known to be good.
    """
    current = _ip(peer)
    if current is None:
        return peer

    def is_trusted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip.version == n.version and ip in n for n in trusted)

    if not is_trusted(current):
        return str(current)
    hops = [h for value in forwarded_for for h in value.split(",") if h.strip()]
    for hop in reversed(hops):
        ip = _ip(hop)
        if ip is None:
            break
        current = ip
        if not is_trusted(ip):
            break
    return str(current)


class GatewayRuntime:
    """Holds the current snapshot and reloads it on change events."""

    def __init__(
        self,
        settings: Settings,
        bus: ConfigBus,
        resolver: AsyncResolver | None = None,
        metrics: MetricsCollector | None = None,
        limiter: Limiter | None = None,
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
        self.trusted_proxies: tuple[IPNetwork, ...] = tuple(
            ipaddress.ip_network(c, strict=False) for c in settings.gateway_trusted_proxies
        )
        self.secret_box: SecretBox | None = load_secret_box(settings)
        self._redis: Any = None
        if limiter is None:
            memory = MemoryLimiter(settings.gateway_rate_limit_max_keys)
            limiter = memory
            if settings.redis_url is not None:
                import redis.asyncio

                self._redis = redis.asyncio.Redis.from_url(
                    settings.redis_url.get_secret_value(),
                    socket_timeout=0.5,
                    socket_connect_timeout=0.5,
                )
                limiter = RedisLimiter(self._redis, memory)
        self.services = PolicyServices(
            limiter=limiter,
            cache=ResponseCache(settings.gateway_cache_max_bytes),
            jwks=JwksCache(lambda: self.client),
        )
        self.trace_listeners: list[TraceListener] = []

    async def reload(self) -> None:
        try:
            snapshot = await anyio.to_thread.run_sync(
                load_snapshot, self._factory, self.services, self.secret_box
            )
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

    def emit_trace(self, ctx: RequestContext, status: int) -> None:
        for listener in self.trace_listeners:
            try:
                listener(ctx, status)
            except Exception:
                log.exception("trace listener failed")

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
            if self._redis is not None:
                with contextlib.suppress(Exception):
                    await self._redis.aclose()
            self._engine.dispose()


def _connection_tokens(headers: Sequence[tuple[bytes, bytes]]) -> set[str]:
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            tokens |= {t.strip().lower() for t in value.decode("latin-1").split(",") if t.strip()}
    return tokens


def _client_headers(request: Request) -> list[tuple[str, str]]:
    """The client's headers that may be forwarded (lower-case names)."""
    raw = request.scope["headers"]
    drop = _REQUEST_DROP | _connection_tokens(raw)
    out = []
    for k, v in raw:
        name = k.decode("latin-1").lower()
        if name not in drop:
            out.append((name, v.decode("latin-1")))
    return out


def _forward_headers(
    ctx: RequestContext, request: Request, prefix: str
) -> list[tuple[bytes, bytes]]:
    out = [
        (k.encode("latin-1"), v.encode("latin-1")) for k, v in ctx.headers if k != "x-forwarded-for"
    ]
    peer = request.client.host if request.client else ""
    prior = ", ".join(v for k, v in ctx.headers if k == "x-forwarded-for")
    if peer:
        chain = f"{prior}, {peer}" if prior else peer
        out.append((b"x-forwarded-for", chain.encode("latin-1")))
    elif prior:
        out.append((b"x-forwarded-for", prior.encode("latin-1")))
    host = request.headers.get("host")
    if host:
        out.append((b"x-forwarded-host", host.encode("latin-1")))
    out.append((b"x-forwarded-proto", request.url.scheme.encode("latin-1")))
    out.append((b"x-forwarded-prefix", quote(prefix, safe=_PATH_SAFE).encode("latin-1")))
    out.append((b"x-request-id", ctx.request_id.encode("latin-1")))
    return out


def _upstream_headers(upstream: httpx.Response) -> list[tuple[str, str]]:
    raw = upstream.headers.raw
    drop = HOP_BY_HOP | _connection_tokens(raw) | {"x-request-id"}
    out = []
    for k, v in raw:
        name = k.decode("latin-1").lower()
        if name not in drop:
            out.append((name, v.decode("latin-1")))
    return out


class _Meter:
    """Measures one request to an API and records it once answered."""

    def __init__(self, metrics: MetricsCollector, api: RuntimeApi, method: str) -> None:
        self.metrics = metrics
        self.api = api
        self.method = method
        self.route = ""
        self.consumer = ""
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
                consumer=self.consumer,
                status=status,
                latency_ms=(time.perf_counter() - self.started) * 1000,
                bytes_in=self.bytes_in,
                bytes_out=bytes_out,
                at=self.at,
            )
        )


def _plain_error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        {"error": code, "message": message, "request_id": request_id},
        status_code=status,
        headers={
            "x-request-id": request_id,
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
    )


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


def _context(
    request: Request,
    runtime: GatewayRuntime,
    api: RuntimeApi,
    method: str,
    remainder: str,
    route: str,
    request_id: str,
) -> RequestContext:
    raw_query = request.scope.get("query_string", b"").decode("latin-1")
    peer = request.client.host if request.client else ""
    limit = runtime.settings.gateway_max_request_body_bytes
    return RequestContext(
        method=method,
        path=remainder,
        route=route,
        query=parse_qsl(raw_query, keep_blank_values=True),
        raw_query=raw_query,
        headers=_client_headers(request),
        client_ip=client_address(
            peer, request.headers.getlist("x-forwarded-for"), runtime.trusted_proxies
        ),
        request_id=request_id,
        tenant_id=api.tenant_id,
        product_id=api.product_id,
        api_id=api.api_id,
        body_reader=lambda: _read_body(request, limit),
    )


def _finish(
    runtime: GatewayRuntime,
    api: RuntimeApi,
    ctx: RequestContext | None,
    resp: GatewayResponse,
    meter: _Meter,
    request_id: str,
) -> Response:
    """Turn a pipeline response into the ASGI response; meter it and emit the trace."""
    headers = [(k, v) for k, v in resp.headers if k != "x-request-id"]
    headers.append(("x-request-id", request_id))
    if api.state == DEPRECATED:
        headers.append(("deprecation", "true"))
    if ctx is not None:
        meter.consumer = ctx.consumer
        runtime.emit_trace(ctx, resp.status)
    stream = resp.stream
    if stream is None:
        body = resp.body or b""
        if resp.error is not None and body == json.dumps(resp.error).encode():
            body = json.dumps({**resp.error, "request_id": request_id}).encode()
        headers = [(k, v) for k, v in headers if k != "content-length"]
        out = Response(content=body, status_code=resp.status)
        out.raw_headers = [
            *((k.encode("latin-1"), v.encode("latin-1")) for k, v in headers),
            (b"content-length", str(len(body)).encode()),
        ]
        meter.finish(resp.status, len(body))
        return out

    async def body_iter() -> AsyncIterator[bytes]:
        sent = 0
        try:
            async for chunk in stream:
                sent += len(chunk)
                yield chunk
        finally:
            await stream.aclose()
            meter.finish(resp.status, sent)

    streaming = StreamingResponse(body_iter(), status_code=resp.status)
    streaming.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers]
    return streaming


async def _upstream_body(upstream: httpx.Response, api: RuntimeApi) -> AsyncGenerator[bytes, None]:
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    except httpx.HTTPError:
        log.warning("upstream response interrupted (api %s)", api.api_id)
    finally:
        await upstream.aclose()


async def _buffer(resp: GatewayResponse, limit: int) -> None:
    """Read up to ``limit`` bytes of a streamed response into ``resp.body``.

    Larger bodies keep streaming (already read chunks first) and are marked too large.
    """
    stream = resp.stream
    if stream is None:
        return
    chunks: list[bytes] = []
    size = 0
    async for chunk in stream:
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            break
    else:
        resp.body = b"".join(chunks)
        resp.stream = None
        return

    async def rest() -> AsyncGenerator[bytes, None]:
        try:
            for chunk in chunks:
                yield chunk
            async for chunk in stream:
                yield chunk
        finally:
            await stream.aclose()

    resp.body = None
    resp.body_too_large = True
    resp.stream = rest()


async def proxy(request: Request) -> Response:
    runtime: GatewayRuntime = request.app.state.runtime
    supplied = request.headers.get("x-request-id", "")
    request_id = supplied if _REQUEST_ID.match(supplied) else uuid.uuid4().hex

    path = request.url.path
    segments = path.split("/")
    if any(seg in (".", "..") for seg in segments) or "\x00" in path:
        return _plain_error(400, "bad_request", "Invalid request path.", request_id)
    slug = segments[1] if len(segments) > 1 else ""
    rest = "/" + "/".join(segments[2:])
    found = runtime.snapshot.resolve(slug, rest)
    if found is None:
        runtime.metrics.record_unmatched()
        return _plain_error(404, "not_found", "No API matches this path.", request_id)
    api, remainder = found
    method = request.method.upper()
    meter = _Meter(runtime.metrics, api, method)

    def done(resp: GatewayResponse, ctx: RequestContext | None = None) -> Response:
        return _finish(runtime, api, ctx, resp, meter, request_id)

    if api.state == RETIRED:
        return done(json_error(410, "api_retired", "This API has been retired."))

    # CORS preflight: answered by the CORS policy of the route the browser asks about.
    preflight_method = request.headers.get("access-control-request-method")
    if method == "OPTIONS" and preflight_method and request.headers.get("origin"):
        target, others = api.match(preflight_method.strip().upper(), remainder)
        if target is None and others:  # the path exists: let its CORS policy refuse the method
            target, _ = api.match(sorted(others)[0], remainder)
        cors = api.pipeline.find(Cors, target.path) if target is not None else None
        if target is not None and isinstance(cors, Cors):
            meter.route = target.path
            ctx = _context(request, runtime, api, method, remainder, target.path, request_id)
            started = time.perf_counter()
            outcome, detail, preflight = cors.preflight(ctx)
            elapsed = (time.perf_counter() - started) * 1000
            ctx.trace.append(TraceEntry(cors.id, cors.type, "request", outcome, detail, elapsed))
            return done(preflight, ctx)

    rule, allowed = api.match(method, remainder)
    if rule is None:
        if not allowed:
            return done(json_error(404, "not_found", "No API matches this path."))
        resp = json_error(405, "method_not_allowed", "Method not allowed.")
        resp.add("allow", ", ".join(sorted(allowed)))
        return done(resp)
    meter.route = rule.path
    ctx = _context(request, runtime, api, method, remainder, rule.path, request_id)
    too_large = json_error(413, "payload_too_large", "Request body is too large.")

    pipeline = api.pipeline
    try:
        answer, ran = await pipeline.run_request(ctx, pipeline.for_route(rule.path))
        if answer is None:
            body = await ctx.body()
            meter.bytes_in = len(body)
            prefix = f"/{slug}{api.base_path}"
            headers = _forward_headers(ctx, request, prefix)
            target_path = quote(remainder, safe=_PATH_SAFE)
            query = urlencode(ctx.query) if ctx.query_changed else ctx.raw_query
            answer = await _send(runtime, api, method, target_path, query, headers, body)
            limit = max((p.response_body_limit(ctx) for p in ran), default=0)
            if limit:
                await _buffer(answer, limit)
    except BodyTooLargeError:
        return done(too_large, ctx)
    original_stream = answer.stream
    final = await pipeline.run_response(ctx, ran, answer)
    if original_stream is not None and final.stream is not original_stream:
        await original_stream.aclose()  # the upstream body is not used: release the connection
    return done(final, ctx)


async def _send(
    runtime: GatewayRuntime,
    api: RuntimeApi,
    method: str,
    target: str,
    query: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> GatewayResponse:
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
        return GatewayResponse(
            status=upstream.status_code,
            headers=_upstream_headers(upstream),
            body=None,
            stream=_upstream_body(upstream, api),
            source="upstream",
        )
    status, code, message = failure
    return json_error(status, code, message)


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
    limiter: Limiter | None = None,
) -> Starlette:
    """The gateway ASGI app. Share ``bus`` with :func:`apiedge.app.create_app` in one process."""
    settings = settings or get_settings()
    redis_url = settings.redis_url.get_secret_value() if settings.redis_url else None
    runtime = GatewayRuntime(settings, bus or build_bus(redis_url), resolver, metrics, limiter)

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
