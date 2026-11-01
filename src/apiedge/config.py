# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration (pydantic-settings).

Settings come from environment variables prefixed ``APIEDGE_`` and, optionally,
a ``.env`` file in the working directory. Data lives in the OS-conventional
user data directory (``platformdirs``) unless ``APIEDGE_DATA_DIR`` overrides it.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from platformdirs import user_data_path
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

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

    @field_validator("data_dir")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    @field_validator(
        "cors_allow_origins",
        "secret_key_previous",
        "ssrf_allow_cidrs",
        "ssrf_deny_cidrs",
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

    @field_validator("ssrf_allow_cidrs", "ssrf_deny_cidrs")
    @classmethod
    def _check_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            ipaddress.ip_network(cidr, strict=False)  # raises ValueError if invalid
        return v

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
