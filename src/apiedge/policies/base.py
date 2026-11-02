# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""The policy pipeline (T-008, ADR 0009).

A :class:`Pipeline` is the ordered list of an API's enabled policies. For one request the
gateway runs every policy that applies to the matched route, in order, on the request; a policy
may answer the request itself (rejection, mock, cache hit), which skips the remaining policies
and the upstream. The response - from the upstream or from a policy - then passes back through
the policies that ran, in reverse order (an onion), so CORS headers, rate-limit headers and
response transforms also apply to answers produced inside the chain.

Every step is recorded in the request's decision trace (:class:`TraceEntry`): policy, phase,
outcome, a short detail and its duration. The packet inspector (T-012) shows it; no trace ever
contains credentials.

A policy that raises fails closed: the request is answered with a generic 500.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal

log = logging.getLogger("apiedge.gateway.policies")

Outcome = Literal["pass", "modify", "skip", "reject", "respond", "error"]


@dataclass(frozen=True)
class TraceEntry:
    policy_id: str
    policy_type: str
    phase: Literal["request", "response"]
    outcome: Outcome
    detail: str
    duration_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "type": self.policy_type,
            "phase": self.phase,
            "outcome": self.outcome,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass(frozen=True)
class Identity:
    """Who the request authenticated as (API key or JWT)."""

    kind: Literal["api-key", "jwt"]
    subject: str  # key id or the JWT's consumer claim
    name: str  # display name (analytics consumer label)
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayResponse:
    """A response on its way back to the client.

    ``body`` is the complete body when known (policy answers, buffered upstream answers);
    otherwise ``stream`` yields it. Header names are lower-case.
    """

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | None = b""
    stream: AsyncGenerator[bytes, None] | None = None
    source: Literal["policy", "upstream", "gateway"] = "policy"
    body_too_large: bool = False  # upstream body exceeded the buffering limit
    error: dict[str, str] | None = None  # gateway error document (request id added on the way out)

    def get(self, name: str) -> str | None:
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def get_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self.headers.append((name, value))

    def add(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def remove(self, name: str) -> None:
        self.headers = [(k, v) for k, v in self.headers if k != name]

    def set_body(self, body: bytes) -> None:
        self.body = body
        self.stream = None
        self.remove("content-length")


def json_error(
    status: int, code: str, message: str, headers: Sequence[tuple[str, str]] = ()
) -> GatewayResponse:
    """A gateway error document (the gateway adds ``x-request-id``)."""
    body = json.dumps({"error": code, "message": message}).encode()
    return GatewayResponse(
        status=status,
        headers=[
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            *headers,
        ],
        body=body,
        source="gateway",
        error={"error": code, "message": message},
    )


class BodyTooLargeError(Exception):
    """The request body exceeds the gateway's limit."""


@dataclass
class RequestContext:
    """One request as the policies see it. Header names are lower-case."""

    method: str
    path: str  # below the API's base path
    route: str  # the matched route's configured path
    query: list[tuple[str, str]]
    raw_query: str  # as received; forwarded unchanged unless a policy changed ``query``
    headers: list[tuple[str, str]]  # forwarded to the upstream (minus the gateway's own)
    client_ip: str
    request_id: str
    tenant_id: int = 0
    product_id: int = 0
    api_id: int = 0
    identity: Identity | None = None
    trace: list[TraceEntry] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)  # per-request policy scratch space
    body_reader: Callable[[], Awaitable[bytes]] | None = None
    _body: bytes | None = None
    query_changed: bool = False
    # Recorded for the packet inspector (T-012); policies do not change these.
    url: str = ""  # the URL as received (scheme, host, gateway path, query)
    received_headers: list[tuple[str, str]] = field(default_factory=list)  # as received
    started_at: float = 0.0  # epoch seconds
    started_perf: float = 0.0  # time.perf_counter() at arrival (durations)
    upstream_url: str = ""  # base URL of the upstream that answered (or was tried last)
    upstream_attempts: int = 0
    upstream_ms: float | None = None  # until the upstream's response headers arrived

    @property
    def body_read(self) -> bytes | None:
        """The request body if it has been read (forwarded or inspected), else None."""
        return self._body

    @property
    def consumer(self) -> str:
        """The analytics consumer label ("" = anonymous)."""
        if self.identity is None:
            return ""
        prefix = "key" if self.identity.kind == "api-key" else "jwt"
        return f"{prefix}:{self.identity.name}"[:128]

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def set_header(self, name: str, value: str) -> None:
        self.remove_header(name)
        self.headers.append((name, value))

    def remove_header(self, name: str) -> None:
        self.headers = [(k, v) for k, v in self.headers if k != name]

    async def body(self) -> bytes:
        """The request body, read on first use (raises :class:`BodyTooLargeError`)."""
        if self._body is None:
            self._body = await self.body_reader() if self.body_reader else b""
        return self._body

    def replace_body(self, body: bytes) -> None:
        self._body = body


class Policy:
    """A configured policy. Subclasses override :meth:`on_request` and/or :meth:`on_response`.

    Both return ``(outcome, detail)`` for the trace; :meth:`on_request` may also return a
    response that answers the request.
    """

    type: ClassVar[str] = ""
    handles_response: ClassVar[bool] = False

    def __init__(self, policy_id: str, routes: frozenset[str]) -> None:
        self.id = policy_id
        self.routes = routes

    def applies(self, route: str) -> bool:
        return not self.routes or route in self.routes

    def response_body_limit(self, ctx: RequestContext) -> int:
        """Bytes of the upstream response this policy needs buffered (0 = none)."""
        return 0

    async def on_request(self, ctx: RequestContext) -> tuple[Outcome, str, GatewayResponse | None]:
        return "pass", "", None

    async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> tuple[Outcome, str]:
        return "pass", ""


class UnavailablePolicy(Policy):
    """Stands in for a policy whose stored configuration cannot be used: fails closed."""

    def __init__(self, policy_id: str, policy_type: str, routes: frozenset[str], why: str) -> None:
        super().__init__(policy_id, routes)
        self.type_name = policy_type
        self.why = why

    async def on_request(self, ctx: RequestContext) -> tuple[Outcome, str, GatewayResponse | None]:
        return (
            "error",
            self.why,
            json_error(503, "policy_unavailable", "The API is not available right now."),
        )


def policy_type(policy: Policy) -> str:
    return policy.type_name if isinstance(policy, UnavailablePolicy) else policy.type


class Pipeline:
    """The ordered, enabled policies of one API."""

    def __init__(self, policies: Sequence[Policy] = ()) -> None:
        self.policies = tuple(policies)

    def __bool__(self) -> bool:
        return bool(self.policies)

    def for_route(self, route: str) -> list[Policy]:
        return [p for p in self.policies if p.applies(route)]

    def find(self, kind: type[Policy], route: str) -> Policy | None:
        for p in self.for_route(route):
            if isinstance(p, kind):
                return p
        return None

    async def run_request(
        self, ctx: RequestContext, policies: Sequence[Policy]
    ) -> tuple[GatewayResponse | None, list[Policy]]:
        """Run the request phase; returns (answer or None, the policies that ran)."""
        ran: list[Policy] = []
        for policy in policies:
            started = time.perf_counter()
            try:
                outcome, detail, answer = await policy.on_request(ctx)
            except BodyTooLargeError:
                raise
            except Exception:
                log.exception("policy %s (%s) failed", policy.id, policy_type(policy))
                outcome, detail = "error", "internal error"
                answer = json_error(500, "policy_error", "The request could not be processed.")
            ctx.trace.append(
                TraceEntry(
                    policy.id,
                    policy_type(policy),
                    "request",
                    outcome,
                    detail,
                    (time.perf_counter() - started) * 1000,
                )
            )
            if answer is not None:
                # A policy that answered does not see its own answer (e.g. a cache hit).
                return answer, ran
            ran.append(policy)
        return None, ran

    async def run_response(
        self, ctx: RequestContext, ran: Sequence[Policy], resp: GatewayResponse
    ) -> GatewayResponse:
        for policy in reversed(ran):
            if not policy.handles_response:
                continue
            started = time.perf_counter()
            try:
                outcome, detail = await policy.on_response(ctx, resp)
            except Exception:
                log.exception("policy %s (%s) failed on the response", policy.id, policy.type)
                ctx.trace.append(
                    TraceEntry(
                        policy.id,
                        policy.type,
                        "response",
                        "error",
                        "internal error",
                        (time.perf_counter() - started) * 1000,
                    )
                )
                return json_error(500, "policy_error", "The response could not be processed.")
            ctx.trace.append(
                TraceEntry(
                    policy.id,
                    policy.type,
                    "response",
                    outcome,
                    detail,
                    (time.perf_counter() - started) * 1000,
                )
            )
        return resp
