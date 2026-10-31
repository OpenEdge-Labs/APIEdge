# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration (pydantic-settings).

Settings come from environment variables prefixed ``APIEDGE_`` and, optionally,
a ``.env`` file in the working directory. Data lives in the OS-conventional
user data directory (``platformdirs``) unless ``APIEDGE_DATA_DIR`` overrides it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from platformdirs import user_data_path
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

    @field_validator("data_dir")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser().resolve()

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
