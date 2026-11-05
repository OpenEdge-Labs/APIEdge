# Copyright 2026 OpenEdge Labs
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

Each served API carries its policy :class:`~apiedge.policies.base.Pipeline` (T-008), built from
the stored chain with the product's active API keys (only their SHA-256 hashes).
"""

from __future__ import annotations

import logging
import re
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.models import Api, ApiKey, Keystore, Product, Tenant, TlsProfile, Truststore
from apiedge.gateway.transport import UpstreamTls, build_profile_context
from apiedge.policies.base import Pipeline
from apiedge.policies.builtin import ApiKeyInfo, PolicyServices, build_pipeline
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.tls import keystore_aad
from apiedge.security.x509 import Certificate, CertificateError, load_pem_certificates

log = logging.getLogger("apiedge.gateway")

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
    # Upstream TLS profile (T-023): None uses the gateway's default client; ``tls_unusable``
    # makes the API answer 503 (a profile whose keystore cannot be decrypted, for example).
    tls: UpstreamTls | None = None
    tls_context: ssl.SSLContext | None = field(default=None, repr=False)
    tls_unusable: bool = False
    pipeline: Pipeline = field(default_factory=Pipeline, repr=False)

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


def build_runtime_api(
    api: Api,
    tenant_slug: str,
    product_lifecycle: str,
    *,
    services: PolicyServices | None = None,
    keys: Mapping[str, ApiKeyInfo] | None = None,
    box: SecretBox | None = None,
    truststores: Mapping[int, tuple[Certificate, ...]] | None = None,
    profiles: Mapping[int, ResolvedProfile] | None = None,
) -> RuntimeApi | None:
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
    pipeline = Pipeline()
    if services is not None and state != RETIRED:
        pipeline = build_pipeline(
            api.policies,
            tenant_id=api.tenant_id,
            api_id=api.id,
            keys=keys or {},
            services=services,
            box=box,
            truststores=truststores,
        )
    resolved: ResolvedProfile | None = None
    if api.tls_profile_id is not None:
        resolved = (profiles or {}).get(api.tls_profile_id, ResolvedProfile(None, None))
    return RuntimeApi(
        tls=resolved.tls if resolved else None,
        tls_context=resolved.context if resolved else None,
        tls_unusable=resolved is not None and resolved.context is None,
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
        pipeline=pipeline,
    )


def _active_keys(session: Session) -> dict[tuple[int, int], dict[str, ApiKeyInfo]]:
    """(tenant, product) -> {key hash -> key} for unrevoked keys (expiry is checked per request)."""
    keys: dict[tuple[int, int], dict[str, ApiKeyInfo]] = {}
    for k in session.scalars(select(ApiKey).where(ApiKey.revoked_at.is_(None))):
        expires = k.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)  # SQLite drops the offset
        info = ApiKeyInfo(k.id, k.name, k.prefix, expires)
        keys.setdefault((k.tenant_id, k.product_id), {})[k.key_hash] = info
    return keys


def _truststores(session: Session) -> dict[int, dict[int, tuple[Certificate, ...]]]:
    """tenant -> {truststore id -> certificates}; unreadable stores are left out (fail closed)."""
    out: dict[int, dict[int, tuple[Certificate, ...]]] = {}
    for t in session.scalars(select(Truststore)):
        try:
            certs = tuple(load_pem_certificates(t.certificates))
        except CertificateError:
            log.error("truststore %s cannot be read; policies using it fail closed", t.id)
            continue
        out.setdefault(t.tenant_id, {})[t.id] = certs
    return out


@dataclass(frozen=True)
class ResolvedProfile:
    """A TLS profile with its client context; ``context`` None: unusable (fail closed)."""

    tls: UpstreamTls | None
    context: ssl.SSLContext | None


def _profiles(
    session: Session, box: SecretBox | None, ca_bundle: Path | None
) -> dict[int, dict[int, ResolvedProfile]]:
    """tenant -> {profile id -> resolved profile}: each API only sees its own tenant's."""
    out: dict[int, dict[int, ResolvedProfile]] = {}
    cache: dict[str, ssl.SSLContext] = {}
    for p in session.scalars(select(TlsProfile)):
        try:
            ca_pem = chain = key_pem = None
            if p.truststore_id is not None:
                store = session.get(Truststore, p.truststore_id)
                if store is None or store.tenant_id != p.tenant_id:
                    raise ValueError("truststore missing")
                ca_pem = store.certificates
            if p.keystore_id is not None:
                ks = session.get(Keystore, p.keystore_id)
                if ks is None or ks.tenant_id != p.tenant_id or box is None:
                    raise ValueError("keystore missing or secrets key not configured")
                chain = ks.certificate_chain
                key_pem = box.decrypt_str(ks.private_key, keystore_aad(ks.tenant_id, ks.id))
            tls = UpstreamTls.make(p.min_version, p.ciphers, ca_pem, chain, key_pem)
            if tls.key not in cache:
                cache[tls.key] = build_profile_context(tls, ca_bundle)
            out.setdefault(p.tenant_id, {})[p.id] = ResolvedProfile(tls, cache[tls.key])
        except (ValueError, OSError, CryptoError):  # ssl.SSLError is an OSError
            log.error("TLS profile %s cannot be used; its APIs answer 503", p.id)
            out.setdefault(p.tenant_id, {})[p.id] = ResolvedProfile(None, None)
    return out


def load_snapshot(
    factory: sessionmaker[Session],
    services: PolicyServices | None = None,
    box: SecretBox | None = None,
    ca_bundle: Path | None = None,
) -> Snapshot:
    """Read every tenant's servable APIs. Runs in a worker thread (blocking DB access).

    The session is not bound to a tenant (platform scope); tenant separation comes from keying
    the result by each API's own tenant.
    """
    tenants: dict[str, list[RuntimeApi]] = {}
    with factory() as session:
        slugs = {t.id: t.slug for t in session.scalars(select(Tenant).where(Tenant.is_active))}
        keys = _active_keys(session) if services is not None else {}
        stores = _truststores(session) if services is not None else {}
        profiles = _profiles(session, box, ca_bundle)
        rows = session.execute(
            select(Api, Product.lifecycle)
            .join(Product, (Product.id == Api.product_id) & (Product.tenant_id == Api.tenant_id))
            .where(Api.lifecycle != "draft")
        ).all()
        for api, product_lifecycle in rows:
            slug = slugs.get(api.tenant_id)
            if slug is None:
                continue
            runtime = build_runtime_api(
                api,
                slug,
                product_lifecycle,
                services=services,
                keys=keys.get((api.tenant_id, api.product_id), {}),
                box=box,
                truststores=stores.get(api.tenant_id, {}),
                profiles=profiles.get(api.tenant_id, {}),
            )
            if runtime is not None:
                tenants.setdefault(slug, []).append(runtime)
    return Snapshot(
        tenants={
            slug: tuple(sorted(apis, key=lambda a: len(a.base_path), reverse=True))
            for slug, apis in tenants.items()
        },
        loaded=True,
    )
