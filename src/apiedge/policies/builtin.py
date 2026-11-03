# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""The built-in policies (T-008, ADR 0009) and the pipeline builder.

| type | request phase | response phase |
|---|---|---|
| ``api-key`` | 401 unless a valid key of the API's product is sent | - |
| ``jwt`` | 401 unless a valid token is sent (503 if keys are unavailable) | - |
| ``rate-limit`` | 429 with ``Retry-After`` beyond the limit | ``RateLimit-*`` headers |
| ``transform`` | headers, query, JSON body fields | headers, JSON body fields |
| ``cors`` | notes an allowed ``Origin`` (preflights are answered before the chain) | CORS headers |
| ``ip-filter`` | 403 for denied or not allowed client addresses | - |
| ``cache`` | answers fresh hits | stores cacheable upstream answers |
| ``mock`` | answers with the configured response | - |
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import TypeAdapter, ValidationError

from apiedge.policies.base import (
    GatewayResponse,
    Identity,
    Outcome,
    Pipeline,
    Policy,
    RequestContext,
    UnavailablePolicy,
    json_error,
)
from apiedge.policies.config import (
    SECRET_FIELDS,
    ApiKeyConfig,
    CacheConfig,
    CorsConfig,
    IpFilterConfig,
    JwtConfig,
    MockConfig,
    MtlsConfig,
    PolicySpec,
    RateLimitConfig,
    TransformConfig,
    is_policy_id,
)
from apiedge.policies.jwt import (
    JwksCache,
    JwtError,
    JwtVerifier,
    KeysUnavailableError,
    VerifyKey,
    load_pem_key,
)
from apiedge.policies.stores import CachedResponse, Limiter, ResponseCache
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.x509 import Certificate, CertificateError, parse_certificate, verify_chain

log = logging.getLogger("apiedge.gateway.policies")

RequestResult = tuple[Outcome, str, GatewayResponse | None]
_SPEC: TypeAdapter[Any] = TypeAdapter(PolicySpec)
_UNSAFE = re.compile(r"[^\x20-\x7e]")


def _safe(value: str, limit: int = 256) -> str:
    """Printable ASCII only: identities from tokens can contain anything."""
    return _UNSAFE.sub("?", value)[:limit]


@dataclass(frozen=True)
class ApiKeyInfo:
    id: int
    name: str
    prefix: str
    expires_at: datetime | None = None


@dataclass
class PolicyServices:
    """Process-wide state shared by all policies (survives configuration reloads)."""

    limiter: Limiter
    cache: ResponseCache
    jwks: JwksCache


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def secret_aad(api_id: int, policy_id: str, field: str) -> str:
    return f"policy:{api_id}:{policy_id}:{field}"


# --------------------------------------------------------------------------- authentication


class ApiKeyAuth(Policy):
    type = "api-key"

    def __init__(
        self,
        policy_id: str,
        routes: frozenset[str],
        config: ApiKeyConfig,
        keys: Mapping[str, ApiKeyInfo],
    ) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.keys = keys

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        cfg = self.config
        value = ctx.header(cfg.header)
        from_query = False
        if value is None and cfg.query_param:
            value = next((v for k, v in ctx.query if k == cfg.query_param), None)
            from_query = value is not None
        challenge = [("www-authenticate", f'APIKey header="{cfg.header}"')]
        if not value:
            return (
                "reject",
                "no API key",
                json_error(401, "unauthorized", "An API key is required.", challenge),
            )
        info = self.keys.get(hash_api_key(value)) if len(value) <= 256 else None
        expires = info.expires_at if info is not None else None
        if expires is not None and expires <= datetime.now(timezone.utc):
            info = None
        if info is None:
            return (
                "reject",
                "unknown, revoked or expired API key",
                json_error(401, "unauthorized", "The API key is not valid.", challenge),
            )
        ctx.identity = Identity("api-key", str(info.id), info.name)
        if cfg.hide_credentials:
            if from_query:
                ctx.query = [(k, v) for k, v in ctx.query if k != cfg.query_param]
                ctx.query_changed = True
            else:
                ctx.remove_header(cfg.header)
        return "pass", f"key {info.prefix}... ({info.name})", None


class ClientCertAuth(Policy):
    """``mtls``: a client certificate that chains to the tenant's truststore (T-023)."""

    type = "mtls"
    _CACHE_MAX = 1024

    def __init__(
        self,
        policy_id: str,
        routes: frozenset[str],
        config: MtlsConfig,
        anchors: tuple[Certificate, ...],
    ) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.anchors = anchors
        self.subjects = frozenset(config.allowed_subjects)
        self.fingerprints = frozenset(config.allowed_fingerprints)
        # DER digest -> (certificate or None, error or None, cache expiry): saves the signature
        # check on every request; entries live at most a minute and never past the expiry.
        self._seen: dict[bytes, tuple[Certificate | None, str | None, float]] = {}

    def _check(self, der: bytes) -> tuple[Certificate | None, str | None]:
        digest = hashlib.sha256(der).digest()
        now = time.time()
        hit = self._seen.get(digest)
        if hit is not None and hit[2] > now:
            return hit[0], hit[1]
        cert: Certificate | None = None
        try:
            cert = parse_certificate(der)
        except CertificateError:
            error: str | None = "unreadable"
            until = now + 60
        else:
            error = verify_chain(cert, self.anchors, purpose="client")
            until = min(now + 60, cert.not_after.timestamp())
        if len(self._seen) >= self._CACHE_MAX:
            self._seen.clear()
        self._seen[digest] = (cert, error, until)
        return cert, error

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        cfg = self.config
        if ctx.client_cert is None:
            return (
                "reject",
                "no client certificate",
                json_error(401, "unauthorized", "A client certificate is required."),
            )
        cert, error = self._check(ctx.client_cert)
        if cert is None or error is not None:
            return (
                "reject",
                f"client certificate {error}",
                json_error(401, "unauthorized", "The client certificate is not valid."),
            )
        if self.fingerprints and cert.fingerprint_sha256 not in self.fingerprints:
            return (
                "reject",
                "certificate not in the allowed list",
                json_error(403, "forbidden", "This client certificate is not allowed."),
            )
        if self.subjects and not ({cert.subject, cert.common_name} & self.subjects):
            return (
                "reject",
                "subject not in the allowed list",
                json_error(403, "forbidden", "This client certificate is not allowed."),
            )
        label = {
            "common_name": cert.common_name or cert.fingerprint_sha256[:16],
            "subject": cert.subject,
            "fingerprint": cert.fingerprint_sha256,
        }[cfg.consumer_from]
        ctx.identity = Identity(
            "mtls", cert.fingerprint_sha256, _safe(label, 128), {"subject": cert.subject}
        )
        if cfg.forward_subject_header:
            ctx.set_header(cfg.forward_subject_header, _safe(cert.subject, 1024))
        return "pass", f"certificate {_safe(cert.common_name or cert.subject, 100)}", None


class JwtAuth(Policy):
    type = "jwt"

    def __init__(
        self, policy_id: str, routes: frozenset[str], config: JwtConfig, verifier: JwtVerifier
    ) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.verifier = verifier

    def _token(self, ctx: RequestContext) -> str | None:
        value = ctx.header(self.config.header)
        if value is None:
            return None
        if self.config.header == "authorization":
            scheme, _, token = value.strip().partition(" ")
            return token.strip() if scheme.lower() == "bearer" and token.strip() else None
        return value.strip() or None

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        token = self._token(ctx)
        if token is None:
            return (
                "reject",
                "no token",
                json_error(
                    401,
                    "unauthorized",
                    "A bearer token is required.",
                    [("www-authenticate", "Bearer")],
                ),
            )
        try:
            claims = await self.verifier.verify(token)
        except JwtError as exc:
            return (
                "reject",
                str(exc),
                json_error(
                    401,
                    "unauthorized",
                    "The token is not valid.",
                    [("www-authenticate", 'Bearer error="invalid_token"')],
                ),
            )
        except KeysUnavailableError as exc:
            return (
                "error",
                f"verification keys unavailable ({exc})",
                json_error(503, "auth_unavailable", "Authentication is unavailable right now."),
            )
        raw = claims.get(self.config.consumer_claim)
        subject = _safe(str(raw), 120) if isinstance(raw, (str, int)) else "unknown"
        ctx.identity = Identity("jwt", subject, subject, claims)
        if self.config.hide_credentials:
            ctx.remove_header(self.config.header)
        return "pass", f"token valid ({self.config.consumer_claim}={subject})", None


# --------------------------------------------------------------------------- traffic


class RateLimit(Policy):
    type = "rate-limit"
    handles_response = True

    def __init__(
        self,
        policy_id: str,
        routes: frozenset[str],
        config: RateLimitConfig,
        limiter: Limiter,
        tenant_id: int,
        api_id: int,
    ) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.limiter = limiter
        self.scope = f"{tenant_id}:{api_id}:{policy_id}"

    def _headers(self, remaining: int, reset: int) -> list[tuple[str, str]]:
        c = self.config
        return [
            ("ratelimit-policy", f"{c.limit};w={c.window_seconds}"),
            ("ratelimit-limit", str(c.limit)),
            ("ratelimit-remaining", str(remaining)),
            ("ratelimit-reset", str(reset)),
        ]

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        c = self.config
        if c.key_by == "api":
            bucket, label = "api", "the API"
        elif c.key_by == "consumer" and ctx.identity is not None:
            bucket = f"c:{ctx.identity.kind}:{ctx.identity.subject}"
            label = "consumer"
        else:
            bucket, label = f"ip:{ctx.client_ip}", "client address"
        window = await self.limiter.hit(f"{self.scope}:{bucket}", c.window_seconds)
        reset = max(1, math.ceil(window.reset_after))
        remaining = max(0, c.limit - window.count)
        ctx.state[self.id] = (remaining, reset)
        if window.count > c.limit:
            return (
                "reject",
                f"limit of {c.limit} per {c.window_seconds}s exceeded (per {label})",
                json_error(
                    429,
                    "rate_limited",
                    "Too many requests.",
                    [("retry-after", str(reset)), *self._headers(0, reset)],
                ),
            )
        return "pass", f"{window.count}/{c.limit} in window (per {label})", None

    async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> tuple[Outcome, str]:
        remaining, reset = ctx.state[self.id]
        for name, value in self._headers(remaining, reset):
            resp.set(name, value)
        return "modify", "rate limit headers"


def _template(value: str, ctx: RequestContext) -> str:
    if "{" not in value:
        return value
    return (
        value.replace("{consumer}", _safe(ctx.consumer))
        .replace("{request_id}", ctx.request_id)
        .replace("{client_ip}", ctx.client_ip)
    )


def _json_edit(document: Any, set_json: Mapping[str, Any], remove_json: list[str]) -> bool:
    if not isinstance(document, dict):
        return False
    for path in remove_json:
        *parents, last = path.split(".")
        node: Any = document
        for p in parents:
            node = node.get(p) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(last, None)
    for path, value in set_json.items():
        *parents, last = path.split(".")
        node = document
        for p in parents:
            child = node.get(p)
            if not isinstance(child, dict):
                child = {}
                node[p] = child
            node = child
        node[last] = value
    return True


def _is_json(content_type: str | None) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


class Transform(Policy):
    type = "transform"
    handles_response = True

    def __init__(self, policy_id: str, routes: frozenset[str], config: TransformConfig) -> None:
        super().__init__(policy_id, routes)
        self.config = config

    def response_body_limit(self, ctx: RequestContext) -> int:
        r = self.config.response
        return r.max_body_bytes if (r.set_json or r.remove_json) else 0

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        r = self.config.request
        done: list[str] = []
        for name in r.remove_headers:
            ctx.remove_header(name)
        for name, value in r.set_headers.items():
            ctx.set_header(name, _template(value, ctx))
        if r.remove_headers or r.set_headers:
            done.append("headers")
        if r.remove_query or r.set_query:
            drop = set(r.remove_query) | set(r.set_query)
            ctx.query = [(k, v) for k, v in ctx.query if k not in drop]
            ctx.query.extend(r.set_query.items())
            ctx.query_changed = True
            done.append("query")
        if r.set_json or r.remove_json:
            body = await ctx.body()
            note = "body skipped (not a JSON object)"
            if body and _is_json(ctx.header("content-type")):
                try:
                    document = json.loads(body)
                except ValueError:
                    document = None
                if _json_edit(document, r.set_json, r.remove_json):
                    ctx.replace_body(json.dumps(document, separators=(",", ":")).encode())
                    note = "body"
            done.append(note)
        return ("modify" if done else "pass"), ", ".join(done), None

    async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> tuple[Outcome, str]:
        r = self.config.response
        done: list[str] = []
        for name in r.remove_headers:
            resp.remove(name)
        for name, value in r.set_headers.items():
            resp.set(name, _template(value, ctx))
        if r.remove_headers or r.set_headers:
            done.append("headers")
        if r.set_json or r.remove_json:
            note = "body skipped (not a JSON object)"
            if resp.body_too_large:
                note = "body skipped (too large)"
            elif resp.get("content-encoding"):
                note = "body skipped (encoded)"
            elif resp.body and _is_json(resp.get("content-type")):
                try:
                    document = json.loads(resp.body)
                except ValueError:
                    document = None
                if _json_edit(document, r.set_json, r.remove_json):
                    resp.set_body(json.dumps(document, separators=(",", ":")).encode())
                    note = "body"
            done.append(note)
        return ("modify" if done else "pass"), ", ".join(done)


_SAFELISTED = frozenset({"accept", "accept-language", "content-language", "content-type"})


class Cors(Policy):
    type = "cors"
    handles_response = True

    def __init__(self, policy_id: str, routes: frozenset[str], config: CorsConfig) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.any_origin = "*" in config.allow_origins
        self.origins = frozenset(config.allow_origins)

    def origin_allowed(self, origin: str) -> bool:
        return self.any_origin or origin.lower().rstrip("/") in self.origins

    def _allow_origin(self, origin: str) -> list[tuple[str, str]]:
        c = self.config
        if self.any_origin and not c.allow_credentials:
            headers = [("access-control-allow-origin", "*")]
        else:
            headers = [("access-control-allow-origin", origin)]
        if c.allow_credentials:
            headers.append(("access-control-allow-credentials", "true"))
        return headers

    def preflight(self, ctx: RequestContext) -> tuple[Outcome, str, GatewayResponse]:
        """Answer a CORS preflight (``OPTIONS`` with ``Access-Control-Request-Method``)."""
        c = self.config
        origin = ctx.header("origin") or ""
        method = (ctx.header("access-control-request-method") or "").strip().upper()
        requested = [
            h.strip().lower()
            for h in (ctx.header("access-control-request-headers") or "").split(",")
            if h.strip()
        ]
        vary = ("vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
        if not self.origin_allowed(origin):
            why = "origin not allowed"
        elif method not in c.allow_methods:
            why = f"method {method or '?'} not allowed"
        elif "*" not in c.allow_headers and any(
            h not in c.allow_headers and h not in _SAFELISTED for h in requested
        ):
            why = "request headers not allowed"
        else:
            headers = [
                *self._allow_origin(origin),
                ("access-control-allow-methods", ", ".join(c.allow_methods)),
                ("access-control-max-age", str(c.max_age_seconds)),
                vary,
            ]
            if requested:
                headers.append(("access-control-allow-headers", ", ".join(requested)))
            return "respond", "preflight allowed", GatewayResponse(204, headers, b"")
        return (
            "reject",
            f"preflight refused: {why}",
            json_error(403, "cors_rejected", "The cross-origin request is not allowed.", [vary]),
        )

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        origin = ctx.header("origin")
        if origin is None:
            return "skip", "no Origin header", None
        if not self.origin_allowed(origin):
            return "skip", "origin not allowed (no CORS headers)", None
        ctx.state[self.id] = origin
        return "pass", "origin allowed", None

    async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> tuple[Outcome, str]:
        origin = ctx.state.get(self.id)
        if origin is None:
            return "skip", ""
        for name, value in self._allow_origin(origin):
            resp.set(name, value)
        if self.config.expose_headers:
            resp.set("access-control-expose-headers", ", ".join(self.config.expose_headers))
        if not (self.any_origin and not self.config.allow_credentials):
            resp.add("vary", "Origin")
        return "modify", "CORS headers"


class IpFilter(Policy):
    type = "ip-filter"

    def __init__(self, policy_id: str, routes: frozenset[str], config: IpFilterConfig) -> None:
        super().__init__(policy_id, routes)
        self.allow = tuple(ipaddress.ip_network(c) for c in config.allow)
        self.deny = tuple(ipaddress.ip_network(c) for c in config.deny)

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        refuse = json_error(403, "forbidden", "Access from this address is not allowed.")
        try:
            ip = ipaddress.ip_address(ctx.client_ip)
        except ValueError:
            return "reject", "client address unknown", refuse
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if any(ip.version == n.version and ip in n for n in self.deny):
            return "reject", f"{ip} is denied", refuse
        if self.allow and not any(ip.version == n.version and ip in n for n in self.allow):
            return "reject", f"{ip} is not allowed", refuse
        return "pass", f"{ip} allowed", None


_CACHEABLE_STATUS = frozenset({200, 203, 204, 300, 301, 404, 405, 410})
_DEFAULT_VARY = ("accept", "accept-encoding")


def _directives(value: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        name, _, arg = part.strip().partition("=")
        if name:
            out[name.lower()] = arg.strip().strip('"')
    return out


def _seconds(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    return int(value)


class Cache(Policy):
    type = "cache"
    handles_response = True

    def __init__(
        self, policy_id: str, routes: frozenset[str], config: CacheConfig, store: ResponseCache
    ) -> None:
        super().__init__(policy_id, routes)
        self.config = config
        self.store = store
        self.vary = tuple(dict.fromkeys([*_DEFAULT_VARY, *config.vary_headers]))
        self.fingerprint = hashlib.sha256(config.model_dump_json().encode()).hexdigest()[:16]

    def response_body_limit(self, ctx: RequestContext) -> int:
        return self.config.max_entry_bytes if self.id in ctx.state else 0

    def _key(self, ctx: RequestContext) -> str:
        if ctx.identity is not None:
            who = f"{ctx.identity.kind}:{ctx.identity.subject}"
        else:
            creds = f"{ctx.header('authorization') or ''}\n{ctx.header('cookie') or ''}"
            who = "anon" if creds == "\n" else hashlib.sha256(creds.encode()).hexdigest()
        parts = [
            str(ctx.tenant_id),
            str(ctx.api_id),
            self.id,
            self.fingerprint,
            ctx.method,
            ctx.path,
            ctx.raw_query,
            who,
            *(f"{h}={ctx.header(h) or ''}" for h in self.vary),
        ]
        return json.dumps(parts)

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        if ctx.method not in ("GET", "HEAD"):
            return "skip", f"{ctx.method} is not cacheable", None
        request_cc = _directives(ctx.header("cache-control"))
        if "no-store" in request_cc:
            return "skip", "request says no-store", None
        authenticated = ctx.identity is not None or bool(
            ctx.header("authorization") or ctx.header("cookie")
        )
        if authenticated and not self.config.cache_authenticated:
            return "skip", "authenticated request", None
        key = self._key(ctx)
        ctx.state[self.id] = key
        revalidate = (
            "no-cache" in request_cc
            or request_cc.get("max-age") == "0"
            or "no-cache" in (ctx.header("pragma") or "").lower()
        )
        if revalidate:
            return "pass", "request asks for a fresh answer", None
        entry = self.store.get(key)
        if entry is None:
            return "pass", "miss", None
        now = time.time()
        resp = GatewayResponse(
            entry.status,
            [*entry.headers, ("age", str(entry.age(now))), ("x-cache", "HIT")],
            b"" if ctx.method == "HEAD" else entry.body,
        )
        return "respond", "hit", resp

    def _ttl(self, resp: GatewayResponse) -> tuple[int, str]:
        if resp.status not in _CACHEABLE_STATUS:
            return 0, f"status {resp.status} not cacheable"
        cc = _directives(resp.get("cache-control"))
        if {"no-store", "no-cache", "private"} & cc.keys():
            return 0, "response forbids caching"
        if resp.get("set-cookie") is not None:
            return 0, "response sets a cookie"
        vary = {v.strip().lower() for v in ",".join(resp.get_all("vary")).split(",") if v.strip()}
        if "*" in vary or not vary <= set(self.vary):
            return 0, "response varies on unconfigured headers"
        if resp.body_too_large or resp.body is None:
            return 0, "response too large"
        ttl = self.config.ttl_seconds
        upstream = _seconds(cc.get("s-maxage")) if "s-maxage" in cc else _seconds(cc.get("max-age"))
        if upstream is not None:
            ttl = min(ttl, upstream)
        return ttl, ""

    async def on_response(self, ctx: RequestContext, resp: GatewayResponse) -> tuple[Outcome, str]:
        key = ctx.state.get(self.id)
        if key is None or resp.source != "upstream":
            return "skip", ""
        resp.set("x-cache", "MISS")
        ttl, why = self._ttl(resp)
        if ttl <= 0:
            return "skip", f"not stored: {why or 'max-age is 0'}"
        assert resp.body is not None  # noqa: S101  # nosec B101 - checked in _ttl
        now = time.time()
        # Headers that belong to this exchange, not to the stored answer.
        headers = [
            (k, v)
            for k, v in resp.headers
            if k not in ("x-request-id", "age", "x-cache", "retry-after")
            and not k.startswith(("access-control-", "ratelimit-"))
        ]
        entry = CachedResponse(resp.status, headers, resp.body, now, now + ttl)
        stored = self.store.put(key, entry)
        return ("modify", f"stored for {ttl}s") if stored else ("skip", "not stored: too large")


class Mock(Policy):
    type = "mock"

    def __init__(self, policy_id: str, routes: frozenset[str], config: MockConfig) -> None:
        super().__init__(policy_id, routes)
        self.config = config

    async def on_request(self, ctx: RequestContext) -> RequestResult:
        c = self.config
        headers = [("content-type", c.content_type), *c.headers.items()]
        body = b"" if ctx.method == "HEAD" else c.body.encode("utf-8")
        return "respond", f"mock {c.status}", GatewayResponse(c.status, headers, body)


# --------------------------------------------------------------------------- builder


def decrypt_secrets(raw: dict[str, Any], api_id: int, box: SecretBox | None) -> dict[str, Any]:
    """A stored chain entry with its secret fields decrypted (raises on failure)."""
    fields = SECRET_FIELDS.get(str(raw.get("type")), ())
    config = raw.get("config")
    if not fields or not isinstance(config, dict):
        return raw
    plain = dict(config)
    for name in fields:
        token = plain.get(name)
        if token is None:
            continue
        if box is None:
            raise CryptoError("secrets encryption is not configured")
        plain[name] = box.decrypt_str(str(token), secret_aad(api_id, str(raw.get("id")), name))
    return {**raw, "config": plain}


def build_policy(
    spec: Any,
    *,
    tenant_id: int,
    api_id: int,
    keys: Mapping[str, ApiKeyInfo],
    services: PolicyServices,
    truststores: Mapping[int, tuple[Certificate, ...]] | None = None,
) -> Policy:
    routes = frozenset(spec.routes)
    pid: str = spec.id
    cfg = spec.config
    if spec.type == "api-key":
        return ApiKeyAuth(pid, routes, cfg, keys)
    if spec.type == "jwt":
        public_key: VerifyKey | None = load_pem_key(cfg.public_key) if cfg.public_key else None
        verifier = JwtVerifier(
            algorithms=frozenset(cfg.algorithms),
            secret=cfg.secret.encode("utf-8") if cfg.secret else None,
            public_key=public_key,
            jwks_url=cfg.jwks_url,
            jwks_ttl=cfg.jwks_cache_seconds,
            jwks=services.jwks,
            issuer=cfg.issuer,
            audiences=frozenset(cfg.audiences),
            require_exp=cfg.require_exp,
            leeway=cfg.leeway_seconds,
        )
        return JwtAuth(pid, routes, cfg, verifier)
    if spec.type == "rate-limit":
        return RateLimit(pid, routes, cfg, services.limiter, tenant_id, api_id)
    if spec.type == "transform":
        return Transform(pid, routes, cfg)
    if spec.type == "cors":
        return Cors(pid, routes, cfg)
    if spec.type == "ip-filter":
        return IpFilter(pid, routes, cfg)
    if spec.type == "cache":
        return Cache(pid, routes, cfg, services.cache)
    if spec.type == "mock":
        return Mock(pid, routes, cfg)
    if spec.type == "mtls":
        anchors = (truststores or {}).get(cfg.truststore_id)
        if not anchors:
            raise ValueError("the policy's truststore does not exist or is empty")
        return ClientCertAuth(pid, routes, cfg, anchors)
    raise ValueError(f"unknown policy type {spec.type}")  # pragma: no cover - union is closed


def build_pipeline(
    stored: str | None,
    *,
    tenant_id: int,
    api_id: int,
    keys: Mapping[str, ApiKeyInfo],
    services: PolicyServices,
    box: SecretBox | None,
    truststores: Mapping[int, tuple[Certificate, ...]] | None = None,
) -> Pipeline:
    """The pipeline for an API's stored chain. Unusable entries fail closed (503)."""
    try:
        entries = json.loads(stored or "[]")
    except ValueError:
        log.error("API %s: stored policy chain is not valid JSON; failing closed", api_id)
        entries = [{"id": "invalid", "type": "invalid"}]
    if not isinstance(entries, list):
        entries = [{"id": "invalid", "type": "invalid"}]
    policies: list[Policy] = []
    for raw in entries:
        raw = raw if isinstance(raw, dict) else {}
        pid = str(raw.get("id")) if is_policy_id(raw.get("id")) else "invalid"
        ptype = str(raw.get("type", "unknown"))[:32]
        routes_raw = raw.get("routes")
        routes = frozenset(
            r for r in (routes_raw if isinstance(routes_raw, list) else []) if isinstance(r, str)
        )
        if raw.get("enabled", True) is False:
            continue
        try:
            spec = _SPEC.validate_python(decrypt_secrets(raw, api_id, box))
            if spec.id is None:
                raise ValueError("policy without an id")
            policies.append(
                build_policy(
                    spec,
                    tenant_id=tenant_id,
                    api_id=api_id,
                    keys=keys,
                    services=services,
                    truststores=truststores,
                )
            )
        except (ValidationError, ValueError, CryptoError) as exc:
            log.error(
                "API %s: policy %s (%s) cannot be used (%s); failing closed",
                api_id,
                pid,
                ptype,
                type(exc).__name__,
            )
            policies.append(UnavailablePolicy(pid, ptype, routes, "configuration unusable"))
    return Pipeline(policies)
