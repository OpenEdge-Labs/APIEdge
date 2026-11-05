# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Policy chain configuration (T-008, ADR 0009): what the admin API accepts and stores.

A policy chain is an ordered list of :data:`PolicySpec` documents stored with the API
(``apis.policies``, JSON). Each entry has a stable ``id`` (assigned by the server), a ``type``,
an optional ``name``, ``enabled``, an optional list of route paths it is limited to and a
type-specific ``config``. The same models validate the chain again when the gateway loads it,
so a hand-edited database row cannot install an invalid policy.

Secret fields (``SECRET_FIELDS``) are stored encrypted with the secrets box and are never
returned by the admin API.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

MAX_POLICIES = 50
MAX_MOCK_BODY = 64 * 1024
MAX_RESPONSE_BODY = 10 * 1024 * 1024

POLICY_TYPES = (
    "api-key",
    "jwt",
    "rate-limit",
    "transform",
    "cors",
    "ip-filter",
    "cache",
    "mock",
    "mtls",
)

# type -> config fields that hold secrets (encrypted at rest, write-only in the admin API).
SECRET_FIELDS: dict[str, tuple[str, ...]] = {"jwt": ("secret",)}

_FIELD_NAME = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$"  # RFC 9110 field-name
HeaderName = Annotated[str, StringConstraints(pattern=_FIELD_NAME, to_lower=True)]
# Visible Latin-1 plus tab and space (RFC 9110 field-value: no CR, LF, NUL or other controls).
HeaderValue = Annotated[
    str, StringConstraints(max_length=4096, pattern=r"^[\t\x20-\x7e\xa0-\xff]*$")
]
QueryName = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^&=#\s]+$")]
QueryValue = Annotated[str, StringConstraints(max_length=1024, pattern=r"^[^\r\n\x00]*$")]
JsonPath = Annotated[
    str,
    StringConstraints(
        max_length=200, pattern=r"^[A-Za-z0-9_$@-]{1,64}(\.[A-Za-z0-9_$@-]{1,64}){0,9}$"
    ),
]
PolicyId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,32}$")]
Origin = Annotated[
    str,
    StringConstraints(max_length=255, pattern=r"^(\*|https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?)$"),
]

# Never set or removed by a transform: the gateway manages these itself (ADR 0007).
RESERVED_REQUEST_HEADERS = frozenset(
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
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-prefix",
        "x-request-id",
    }
)
RESERVED_RESPONSE_HEADERS = RESERVED_REQUEST_HEADERS - {"x-forwarded-for"} | {"content-encoding"}

HMAC_ALGS = ("HS256", "HS384", "HS512")
ASYM_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
JwtAlg = Literal[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _cidrs(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            out.append(str(ipaddress.ip_network(v.strip(), strict=False)))
        except ValueError as exc:
            raise ValueError(f"{v!r} is not an IP address or CIDR range") from exc
    return out


def _headers_ok(names: list[str], reserved: frozenset[str]) -> None:
    bad = sorted({n for n in names if n in reserved})
    if bad:
        raise ValueError(f"headers managed by the gateway cannot be changed: {', '.join(bad)}")


# --------------------------------------------------------------------------- configs


class ApiKeyConfig(_Strict):
    """Requires an API key of the API's product (``admin.policies`` issues them)."""

    header: HeaderName = "x-api-key"
    query_param: QueryName | None = None  # off by default: query strings end up in logs
    hide_credentials: bool = True  # do not forward the key to the upstream


class JwtConfig(_Strict):
    algorithms: list[JwtAlg] = Field(min_length=1, max_length=12)
    secret: str | None = Field(default=None, max_length=1024)  # HS*: shared secret
    public_key: str | None = Field(default=None, max_length=16 * 1024)  # RS/PS/ES: PEM
    jwks_url: str | None = Field(default=None, max_length=2048)  # RS/PS/ES: https JWKS
    jwks_cache_seconds: int = Field(default=300, ge=60, le=86400)
    issuer: str | None = Field(default=None, max_length=500)
    audiences: list[Annotated[str, StringConstraints(max_length=500)]] = Field(
        default_factory=list, max_length=20
    )
    require_exp: bool = True
    leeway_seconds: int = Field(default=30, ge=0, le=300)
    header: HeaderName = "authorization"  # "Bearer <token>" in Authorization, else raw
    consumer_claim: Annotated[str, StringConstraints(min_length=1, max_length=64)] = "sub"
    hide_credentials: bool = False
    # Validate tokens of the tenant's own OAuth 2.0 / OIDC server (T-023): its JWKS and issuer
    # are used; no key, JWKS URL or issuer may be configured.
    builtin_issuer: bool = False

    @field_validator("algorithms")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))

    @field_validator("jwks_url")
    @classmethod
    def _https(cls, v: str | None) -> str | None:
        if v is not None and not v.lower().startswith("https://"):
            raise ValueError("the JWKS URL must use https")
        return v

    @model_validator(mode="after")
    def _keys(self) -> JwtConfig:
        hmac = [a for a in self.algorithms if a in HMAC_ALGS]
        asym = [a for a in self.algorithms if a in ASYM_ALGS]
        if self.builtin_issuer:
            if self.algorithms != ["RS256"]:
                raise ValueError("the built-in issuer signs with RS256 only")
            if self.secret or self.public_key or self.jwks_url or self.issuer:
                raise ValueError(
                    "the built-in issuer brings its own keys and issuer: leave the secret, "
                    "public key, JWKS URL and issuer empty"
                )
            return self
        if hmac and asym:
            # Mixing them invites algorithm-confusion attacks (a public key used as HMAC key).
            raise ValueError("do not mix HS* with RS*/PS*/ES* algorithms in one policy")
        if asym and not (self.public_key or self.jwks_url):
            raise ValueError("RS*, PS* and ES* algorithms need a public key or a JWKS URL")
        if asym and self.public_key and self.jwks_url:
            raise ValueError("configure either a public key or a JWKS URL, not both")
        if hmac and (self.public_key or self.jwks_url):
            raise ValueError("HS* algorithms use a shared secret, not a public key or JWKS")
        if self.secret is not None and len(self.secret.encode("utf-8")) < 32:
            raise ValueError("the shared secret must be at least 32 bytes long")
        return self


class RateLimitConfig(_Strict):
    limit: int = Field(ge=1, le=1_000_000_000)
    window_seconds: int = Field(default=60, ge=1, le=30 * 86400)
    key_by: Literal["consumer", "ip", "api"] = "consumer"  # consumer: falls back to the IP


class _Headers(_Strict):
    set_headers: dict[HeaderName, HeaderValue] = Field(default_factory=dict, max_length=50)
    remove_headers: list[HeaderName] = Field(default_factory=list, max_length=50)
    set_json: dict[JsonPath, Any] = Field(default_factory=dict, max_length=50)
    remove_json: list[JsonPath] = Field(default_factory=list, max_length=50)


class RequestTransform(_Headers):
    set_query: dict[QueryName, QueryValue] = Field(default_factory=dict, max_length=50)
    remove_query: list[QueryName] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _reserved(self) -> RequestTransform:
        _headers_ok([*self.set_headers, *self.remove_headers], RESERVED_REQUEST_HEADERS)
        return self


class ResponseTransform(_Headers):
    max_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=MAX_RESPONSE_BODY)

    @model_validator(mode="after")
    def _reserved(self) -> ResponseTransform:
        _headers_ok([*self.set_headers, *self.remove_headers], RESERVED_RESPONSE_HEADERS)
        return self


class TransformConfig(_Strict):
    request: RequestTransform = Field(default_factory=RequestTransform)
    response: ResponseTransform = Field(default_factory=ResponseTransform)


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _cors_methods() -> list[HttpMethod]:
    return ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]


class CorsConfig(_Strict):
    allow_origins: list[Origin] = Field(min_length=1, max_length=100)
    allow_methods: list[HttpMethod] = Field(default_factory=_cors_methods, min_length=1)
    allow_headers: list[HeaderName] = Field(default_factory=list, max_length=50)
    expose_headers: list[HeaderName] = Field(default_factory=list, max_length=50)
    allow_credentials: bool = False
    max_age_seconds: int = Field(default=600, ge=0, le=86400)

    @field_validator("allow_origins")
    @classmethod
    def _origins(cls, v: list[str]) -> list[str]:
        return [o if o == "*" else o.lower().rstrip("/") for o in v]

    @model_validator(mode="after")
    def _wildcard(self) -> CorsConfig:
        if self.allow_credentials and "*" in self.allow_origins:
            raise ValueError("credentials cannot be allowed for every origin ('*')")
        return self


class IpFilterConfig(_Strict):
    allow: list[str] = Field(default_factory=list, max_length=200)
    deny: list[str] = Field(default_factory=list, max_length=200)

    _a = field_validator("allow", "deny")(_cidrs)

    @model_validator(mode="after")
    def _some(self) -> IpFilterConfig:
        if not (self.allow or self.deny):
            raise ValueError("list at least one allowed or denied address range")
        return self


class CacheConfig(_Strict):
    ttl_seconds: int = Field(default=60, ge=1, le=86400)
    max_entry_bytes: int = Field(default=1024 * 1024, ge=1024, le=MAX_RESPONSE_BODY)
    vary_headers: list[HeaderName] = Field(default_factory=list, max_length=20)
    cache_authenticated: bool = False  # cache responses to authenticated requests, per caller


class MockConfig(_Strict):
    status: int = Field(default=200, ge=200, le=599)
    content_type: HeaderValue = "application/json"
    headers: dict[HeaderName, HeaderValue] = Field(default_factory=dict, max_length=50)
    body: str = Field(default="", max_length=MAX_MOCK_BODY)

    @model_validator(mode="after")
    def _reserved(self) -> MockConfig:
        _headers_ok(list(self.headers), RESERVED_RESPONSE_HEADERS | {"content-type"})
        return self


Fingerprint = Annotated[
    str, StringConstraints(strip_whitespace=True, to_lower=True, pattern=r"^[0-9a-f]{64}$")
]


class MtlsConfig(_Strict):
    """Requires a client certificate issued by a CA of one of the tenant's truststores (T-023)."""

    truststore_id: int = Field(ge=1)
    # Optional allow-lists: the certificate's subject DN or common name, and SHA-256 fingerprints.
    allowed_subjects: list[Annotated[str, StringConstraints(min_length=1, max_length=500)]] = Field(
        default_factory=list, max_length=200
    )
    allowed_fingerprints: list[Fingerprint] = Field(default_factory=list, max_length=200)
    consumer_from: Literal["common_name", "subject", "fingerprint"] = "common_name"
    # Send the verified subject DN to the upstream in this header (any client value is replaced).
    forward_subject_header: HeaderName | None = None

    @model_validator(mode="after")
    def _reserved(self) -> MtlsConfig:
        if self.forward_subject_header:
            _headers_ok([self.forward_subject_header], RESERVED_REQUEST_HEADERS)
        return self


# --------------------------------------------------------------------------- chain entries


class _Spec(_Strict):
    id: PolicyId | None = None
    name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] = ""
    enabled: bool = True
    routes: list[Annotated[str, StringConstraints(min_length=1, max_length=500)]] = Field(
        default_factory=list, max_length=200
    )  # route paths as configured on the API; empty = every route


class ApiKeyPolicy(_Spec):
    type: Literal["api-key"]
    config: ApiKeyConfig = Field(default_factory=ApiKeyConfig)


class JwtPolicy(_Spec):
    type: Literal["jwt"]
    config: JwtConfig


class RateLimitPolicy(_Spec):
    type: Literal["rate-limit"]
    config: RateLimitConfig


class TransformPolicy(_Spec):
    type: Literal["transform"]
    config: TransformConfig = Field(default_factory=TransformConfig)


class CorsPolicy(_Spec):
    type: Literal["cors"]
    config: CorsConfig


class IpFilterPolicy(_Spec):
    type: Literal["ip-filter"]
    config: IpFilterConfig


class CachePolicy(_Spec):
    type: Literal["cache"]
    config: CacheConfig = Field(default_factory=CacheConfig)


class MockPolicy(_Spec):
    type: Literal["mock"]
    config: MockConfig = Field(default_factory=MockConfig)


class MtlsPolicy(_Spec):
    type: Literal["mtls"]
    config: MtlsConfig


PolicySpec = Annotated[
    Union[  # noqa: UP007 - pydantic discriminated union
        ApiKeyPolicy,
        JwtPolicy,
        RateLimitPolicy,
        TransformPolicy,
        CorsPolicy,
        IpFilterPolicy,
        CachePolicy,
        MockPolicy,
        MtlsPolicy,
    ],
    Field(discriminator="type"),
]


class PolicyChain(_Strict):
    policies: list[PolicySpec] = Field(default_factory=list, max_length=MAX_POLICIES)

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyChain:
        ids = [p.id for p in self.policies if p.id is not None]
        if len(ids) != len(set(ids)):
            raise ValueError("policy ids must be unique")
        return self


_ID = re.compile(r"^[a-z0-9]{1,32}$")


def is_policy_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID.match(value))
