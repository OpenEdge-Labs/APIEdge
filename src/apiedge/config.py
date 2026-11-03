# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration (pydantic-settings).

Settings come from environment variables prefixed ``APIEDGE_`` and, optionally,
a ``.env`` file in the working directory. Data lives in the OS-conventional
user data directory (``platformdirs``) unless ``APIEDGE_DATA_DIR`` overrides it.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from platformdirs import user_data_path
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from apiedge.security.ssrf import SsrfPolicy

APP_NAME = "APIEdge"


def default_data_dir() -> Path:
    """OS-conventional data directory, e.g. ``%LOCALAPPDATA%\\APIEdge\\APIEdge`` on Windows."""
    return user_data_path(APP_NAME, appauthor=APP_NAME)


class Settings(BaseSettings):
    """All APIEdge settings. Document every new field in ``.env.example``."""

    model_config = SettingsConfigDict(
        env_prefix="APIEDGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "production"] = "production"
    data_dir: Path = Field(default_factory=default_data_dir)
    database_url: str | None = None
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"
    log_format: Literal["json", "text"] = "json"

    # --- Native TLS (T-023, ADR 0013). PEM files; certificate and key both or neither.
    # Console / admin API listener:
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    tls_key_password: SecretStr | None = None
    # Both listeners: lowest TLS version accepted and the TLS 1.2 cipher list (OpenSSL syntax).
    tls_min_version: Literal["1.2", "1.3"] = "1.2"
    tls_ciphers: str | None = None
    # Gateway listener:
    gateway_tls_cert_file: Path | None = None
    gateway_tls_key_file: Path | None = None
    gateway_tls_key_password: SecretStr | None = None
    # Client certificates on the gateway listener (mTLS): none, optional (asked for, checked by
    # the API's mtls policy) or required (the handshake fails without one). Certificates must
    # chain to the CA bundle below; each API's mtls policy then checks the tenant's truststore.
    gateway_tls_client_auth: Literal["none", "optional", "required"] = "none"
    gateway_tls_client_ca_file: Path | None = None
    # Behind a TLS-terminating proxy: request header carrying the client certificate
    # (URL-encoded PEM, e.g. nginx $ssl_client_escaped_cert). Read only from
    # APIEDGE_GATEWAY_TRUSTED_PROXIES and never forwarded upstream. Empty: off.
    gateway_client_cert_header: str | None = None

    # --- HTTP hardening (T-002). Comma-separated lists in the environment.
    cors_allow_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    max_request_body_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=1024**3)
    hsts_max_age: int = Field(default=31_536_000, ge=0)

    # --- Secrets encryption at rest (T-002, ADR 0003).
    secret_key: SecretStr | None = None
    secret_key_previous: Annotated[list[SecretStr], NoDecode] = Field(default_factory=list)
    secret_key_file: Path | None = None

    # --- SSRF guard for upstream URLs (T-002).
    ssrf_allow_private: bool = False
    ssrf_allow_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    ssrf_deny_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Console authentication (T-003).
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_hours: int = Field(default=12, ge=1, le=24 * 30)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)
    login_rate_limit_per_minute: int = Field(default=20, ge=1, le=10_000)
    # HS256 signing key for access tokens. Default: derived from the secrets master key; without
    # one, a random per-process key (sessions end when APIEdge restarts).
    jwt_secret: SecretStr | None = None
    # Always mark auth cookies Secure (set this behind a TLS-terminating proxy); they are
    # Secure automatically when the request itself is HTTPS.
    cookie_secure: bool = False
    # Reverse proxies in front of the console / admin API (IPs or CIDRs). Only requests whose
    # direct peer is listed may set the client address and scheme with X-Forwarded-For / -Proto
    # (login throttling, audit addresses, cookie and CSRF scheme checks). Empty: forwarded headers
    # are ignored. The default keeps a reverse proxy on the same host working (T-018).
    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["127.0.0.1"])

    # --- Gateway runtime (T-007, ADR 0007).
    gateway_enabled: bool = True
    gateway_host: str = "127.0.0.1"
    gateway_port: int = Field(default=8081, ge=1, le=65535)
    gateway_max_request_body_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=1024**3)
    # Extra attempts after a failed upstream call (connection failures for every method;
    # timeouts and 502/503/504 answers only for idempotent methods).
    gateway_retries: int = Field(default=1, ge=0, le=5)
    # PEM file of CA certificates trusted for HTTPS upstreams (default: the public CA bundle).
    # Upstream certificates are always verified.
    gateway_ca_bundle: Path | None = None
    # Safety-net reload of the gateway configuration in seconds (0 = only on change events).
    gateway_reload_interval_seconds: int = Field(default=30, ge=0, le=3600)
    # Redis for configuration change events across processes, e.g. redis://localhost:6379/0.
    # Without it, changes reach the gateway in the same process immediately and other
    # processes through the periodic reload.
    redis_url: SecretStr | None = None
    # --- Gateway policies (T-008, ADR 0009).
    # Reverse proxies / load balancers in front of the gateway (CIDRs). Only when the direct peer
    # is one of them is X-Forwarded-For used to find the client address (IP filter, rate limits).
    gateway_trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Memory for the response cache policy, per gateway process (0 = caching off).
    gateway_cache_max_bytes: int = Field(default=64 * 1024 * 1024, ge=0, le=16 * 1024**3)
    # Fixed windows kept in memory by the rate-limit policy (without Redis, or as its fallback).
    gateway_rate_limit_max_keys: int = Field(default=100_000, ge=100, le=10_000_000)

    # --- Analytics (T-013, ADR 0008).
    # How often the gateway writes its per-minute aggregates to the database (seconds).
    analytics_flush_interval_seconds: int = Field(default=10, ge=1, le=300)
    # Aggregates older than this are deleted (checked at most hourly).
    analytics_retention_days: int = Field(default=30, ge=1, le=3650)
    # Bearer token for the Prometheus endpoint GET /metrics; unset = the endpoint is off (404).
    metrics_token: SecretStr | None = None

    # --- Packet inspector (T-012, ADR 0010).
    # How often the gateway picks up capture sessions and writes captured exchanges (seconds).
    inspector_poll_interval_seconds: float = Field(default=1.0, ge=0.1, le=60)
    # Upper limits a capture session may ask for.
    inspector_max_duration_minutes: int = Field(default=60, ge=1, le=1440)
    inspector_max_exchanges: int = Field(default=1000, ge=1, le=100_000)
    inspector_max_body_bytes: int = Field(default=64 * 1024, ge=0, le=1024 * 1024)
    inspector_max_active_sessions: int = Field(default=10, ge=1, le=1000)
    # Captured exchanges are deleted this long after their session ended.
    inspector_retention_hours: int = Field(default=24, ge=1, le=24 * 90)
    # Memory the gateway may hold for captured exchanges not yet written (dropped beyond it).
    inspector_queue_max_bytes: int = Field(default=16 * 1024 * 1024, ge=64 * 1024, le=1024**3)
    # Extra JSON field / header / parameter names masked in every capture (comma separated).
    inspector_mask_fields: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("data_dir")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    @field_validator(
        "cors_allow_origins",
        "secret_key_previous",
        "ssrf_allow_cidrs",
        "ssrf_deny_cidrs",
        "trusted_proxies",
        "gateway_trusted_proxies",
        "inspector_mask_fields",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("cors_allow_origins")
    @classmethod
    def _check_origins(cls, v: list[str]) -> list[str]:
        out = []
        for origin in v:
            parts = urlsplit(origin)
            if (
                origin == "*"
                or parts.scheme not in ("http", "https")
                or not parts.hostname
                or parts.path not in ("", "/")
                or parts.query
                or parts.username
            ):
                raise ValueError(f"invalid CORS origin {origin!r}: use scheme://host[:port]")
            out.append(origin.rstrip("/"))
        return out

    @field_validator(
        "ssrf_allow_cidrs", "ssrf_deny_cidrs", "trusted_proxies", "gateway_trusted_proxies"
    )
    @classmethod
    def _check_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            ipaddress.ip_network(cidr, strict=False)  # raises ValueError if invalid
        return v

    @field_validator("metrics_token")
    @classmethod
    def _check_metrics_token(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None or not v.get_secret_value():
            return None
        if len(v.get_secret_value()) < 16:
            raise ValueError("the metrics token must be at least 16 characters long")
        return v

    @field_validator("gateway_client_cert_header")
    @classmethod
    def _check_cert_header(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", v):
            raise ValueError("the client certificate header must be a plain header name")
        return v.lower()

    @field_validator("tls_ciphers")
    @classmethod
    def _check_ciphers(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not re.fullmatch(r"[A-Za-z0-9+:!@=_-]{1,2000}", v):
            raise ValueError("invalid cipher list")
        return v

    @model_validator(mode="after")
    def _check_tls(self) -> Settings:
        for prefix in ("tls", "gateway_tls"):
            cert = getattr(self, f"{prefix}_cert_file")
            key = getattr(self, f"{prefix}_key_file")
            if (cert is None) != (key is None):
                name = f"APIEDGE_{prefix.upper()}"
                raise ValueError(f"set both {name}_CERT_FILE and {name}_KEY_FILE, or neither")
        if self.gateway_tls_client_auth != "none":
            if self.gateway_tls_cert_file is None:
                raise ValueError("client certificate authentication needs gateway TLS")
            if self.gateway_tls_client_ca_file is None:
                raise ValueError("set APIEDGE_GATEWAY_TLS_CLIENT_CA_FILE for client certificates")
        return self

    @property
    def console_tls(self) -> bool:
        return self.tls_cert_file is not None

    @property
    def gateway_tls(self) -> bool:
        return self.gateway_tls_cert_file is not None

    @property
    def effective_secret_key_file(self) -> Path:
        return self.secret_key_file or (self.data_dir / "secret.key")

    @property
    def effective_database_url(self) -> str:
        """SQLite in the data dir by default; PostgreSQL via ``postgresql+psycopg://...``."""
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'apiedge.db').as_posix()}"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def ssrf_policy(self) -> SsrfPolicy:
        """The SSRF guard policy for upstream URLs (admin API checks, gateway connects)."""
        return SsrfPolicy.from_strings(
            allow_private=self.ssrf_allow_private,
            allow_cidrs=self.ssrf_allow_cidrs,
            deny_cidrs=self.ssrf_deny_cidrs,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
