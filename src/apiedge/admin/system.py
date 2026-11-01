# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""``/api/v1/system/settings``: read-only view of the effective configuration (T-004).

| Route | Permission |
|---|---|
| ``GET /system/settings`` | ``settings:read`` platform-wide (SuperAdmins) |

Settings come from the environment (``APIEDGE_*``) and are changed there, not through the API.
Secrets are never returned: only whether they are configured. The database URL is reduced to its
backend name because it can embed credentials.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from apiedge import __version__
from apiedge.admin.deps import Caller, get_settings_dep, require_platform
from apiedge.config import Settings

router = APIRouter(prefix="/system", tags=["system"])


class SettingOut(BaseModel):
    name: str
    value: str
    group: str


def _db_backend(url: str) -> str:
    scheme = url.split(":", 1)[0]
    return scheme.split("+", 1)[0] or "unknown"


def settings_view(s: Settings) -> list[SettingOut]:
    """The non-secret settings shown in the console, grouped for display."""
    rows: list[tuple[str, str, object]] = [
        ("General", "version", __version__),
        ("General", "env", s.env),
        ("General", "data_dir", s.data_dir),
        ("General", "database", _db_backend(s.effective_database_url)),
        ("General", "host", s.host),
        ("General", "port", s.port),
        ("General", "log_level", s.log_level),
        ("General", "log_format", s.log_format),
        ("HTTP", "cors_allow_origins", ", ".join(s.cors_allow_origins) or "(none)"),
        ("HTTP", "max_request_body_bytes", s.max_request_body_bytes),
        ("HTTP", "hsts_max_age", s.hsts_max_age),
        ("HTTP", "cookie_secure", s.cookie_secure),
        ("Secrets", "secret_key", "configured" if s.secret_key else "key file"),
        ("Secrets", "secret_key_previous", f"{len(s.secret_key_previous)} key(s)"),
        ("Secrets", "jwt_secret", "configured" if s.jwt_secret else "derived"),
        ("SSRF guard", "ssrf_allow_private", s.ssrf_allow_private),
        ("SSRF guard", "ssrf_allow_cidrs", ", ".join(s.ssrf_allow_cidrs) or "(none)"),
        ("SSRF guard", "ssrf_deny_cidrs", ", ".join(s.ssrf_deny_cidrs) or "(none)"),
        ("Sign-in", "access_token_ttl_seconds", s.access_token_ttl_seconds),
        ("Sign-in", "refresh_token_ttl_hours", s.refresh_token_ttl_hours),
        ("Sign-in", "login_max_failures", s.login_max_failures),
        ("Sign-in", "login_lockout_minutes", s.login_lockout_minutes),
        ("Sign-in", "login_rate_limit_per_minute", s.login_rate_limit_per_minute),
    ]
    return [
        SettingOut(group=g, name=n, value=str(v).lower() if isinstance(v, bool) else str(v))
        for g, n, v in rows
    ]


@router.get("/settings", response_model=list[SettingOut], summary="Effective settings (no secrets)")
def get_system_settings(
    _caller: Annotated[Caller, Depends(require_platform("settings:read"))],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> list[SettingOut]:
    return settings_view(settings)
