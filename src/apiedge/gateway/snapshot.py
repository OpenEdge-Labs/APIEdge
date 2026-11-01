# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""The gateway's routing snapshot (T-007, ADR 0007).

A :class:`Snapshot` is an immutable view of everything the gateway serves, built from the
database by :func:`load_snapshot` and swapped atomically on reload. Requests are addressed as
``/<tenant slug><API base path><route path>``.

Which APIs are visible (OWASP API9, ADR 0006 lifecycle):

* published API in a product that is not retired: served;
* deprecated API, or a published API of a deprecated product: served with a ``Deprecation``
  header;
* retired API, or any API of a retired product: answered with 410 Gone;
* draft APIs and APIs of inactive tenants: unknown (404).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.models import Api, Product, Tenant

SERVED = "served"
DEPRECATED = "deprecated"
RETIRED = "retired"

_PARAM = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")


def compile_route_path(path: str) -> re.Pattern[str]:
    """``/orders/{id}`` -> one segment per parameter; a final ``/*`` matches the path and below."""
    wildcard = path.endswith("/*")
    body = path[:-2] if wildcard else path
    pattern = "".join(
        "/" + ("[^/]+" if _PARAM.match(seg) else re.escape(seg)) for seg in body.split("/")[1:]
    )
    if wildcard:
        pattern += "(?:/.*)?"
    return re.compile(pattern or "/")


@dataclass(frozen=True)
class RouteRule:
    methods: frozenset[str]
    pattern: re.Pattern[str]
    path: str = ""  # as configured, e.g. /orders/{id} (analytics dimension)


@dataclass(frozen=True)
class Upstream:
    url: str  # scheme://host[:port][/path], without a trailing slash
    weight: int


class WeightedBalancer:
    """Smooth weighted round-robin: deterministic, spreads picks evenly by weight."""

    def __init__(self, weights: Sequence[int]) -> None:
        self._weights = list(weights)
        self._current = [0] * len(weights)

    def pick(self, exclude: frozenset[int] = frozenset()) -> int:
        candidates = [i for i in range(len(self._weights)) if i not in exclude]
        if not candidates:
            candidates = list(range(len(self._weights)))
        total = 0
        best = candidates[0]
        for i in candidates:
            self._current[i] += self._weights[i]
            total += self._weights[i]
            if self._current[i] > self._current[best]:
                best = i
        self._current[best] -= total
        return best


@dataclass
class RuntimeApi:
    api_id: int
    tenant_slug: str
    base_path: str
    state: str  # SERVED, DEPRECATED or RETIRED
    timeout_seconds: float
    upstreams: tuple[Upstream, ...]
    routes: tuple[RouteRule, ...]
    balancer: WeightedBalancer = field(repr=False)
    tenant_id: int = 0
    product_id: int = 0

    def remainder(self, path: str) -> str | None:
        """The path below the base path, or None if ``path`` is not under it."""
        if path == self.base_path:
            return "/"
        if path.startswith(self.base_path + "/"):
            return path[len(self.base_path) :]
        return None

    def match(self, method: str, path: str) -> tuple[RouteRule | None, frozenset[str]]:
        """(matching rule or None, methods allowed on this path). Empty set: no route matches."""
        allowed: set[str] = set()
        for rule in self.routes:
            if rule.pattern.fullmatch(path):
                if method in rule.methods:
                    return rule, rule.methods
                allowed |= rule.methods
        return None, frozenset(allowed)


@dataclass(frozen=True)
class Snapshot:
    tenants: dict[str, tuple[RuntimeApi, ...]] = field(default_factory=dict)
    loaded: bool = False

    def resolve(self, tenant_slug: str, path: str) -> tuple[RuntimeApi, str] | None:
        for api in self.tenants.get(tenant_slug, ()):  # longest base path first
            rest = api.remainder(path)
            if rest is not None:
                return api, rest
        return None


def _state(api_lifecycle: str, product_lifecycle: str) -> str | None:
    if api_lifecycle == "retired" or product_lifecycle == "retired":
        return RETIRED
    if api_lifecycle == "deprecated" or product_lifecycle == "deprecated":
        return DEPRECATED
    if api_lifecycle == "published":
        return SERVED
    return None  # draft


def build_runtime_api(api: Api, tenant_slug: str, product_lifecycle: str) -> RuntimeApi | None:
    state = _state(api.lifecycle, product_lifecycle)
    if state is None:
        return None
    upstreams = tuple(Upstream(u.url.rstrip("/"), u.weight) for u in api.upstreams)
    routes = tuple(
        RouteRule(frozenset(r.methods.split(",")), compile_route_path(r.path), r.path)
        for r in api.routes
    )
    if state != RETIRED and not (upstreams and routes):
        return None
    return RuntimeApi(
        api_id=api.id,
        tenant_slug=tenant_slug,
        base_path=api.base_path.rstrip("/"),
        state=state,
        timeout_seconds=api.timeout_ms / 1000,
        upstreams=upstreams,
        routes=routes,
        balancer=WeightedBalancer([u.weight for u in upstreams]),
        tenant_id=api.tenant_id,
        product_id=api.product_id,
    )


def load_snapshot(factory: sessionmaker[Session]) -> Snapshot:
    """Read every tenant's servable APIs. Runs in a worker thread (blocking DB access).

    The session is not bound to a tenant (platform scope); tenant separation comes from keying
    the result by each API's own tenant.
    """
    tenants: dict[str, list[RuntimeApi]] = {}
    with factory() as session:
        slugs = {t.id: t.slug for t in session.scalars(select(Tenant).where(Tenant.is_active))}
        rows = session.execute(
            select(Api, Product.lifecycle)
            .join(Product, (Product.id == Api.product_id) & (Product.tenant_id == Api.tenant_id))
            .where(Api.lifecycle != "draft")
        ).all()
        for api, product_lifecycle in rows:
            slug = slugs.get(api.tenant_id)
            if slug is None:
                continue
            runtime = build_runtime_api(api, slug, product_lifecycle)
            if runtime is not None:
                tenants.setdefault(slug, []).append(runtime)
    return Snapshot(
        tenants={
            slug: tuple(sorted(apis, key=lambda a: len(a.base_path), reverse=True))
            for slug, apis in tenants.items()
        },
        loaded=True,
    )
