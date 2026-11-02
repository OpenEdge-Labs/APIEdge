# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Stored exchange format and its encryption (T-012, ADR 0010).

A captured exchange is a JSON document::

    {
      "request":  {"method", "url", "path", "query", "headers": [[name, value]...],
                   "body": BODY, "upstream_path", "upstream_query",
                   "upstream_headers": [[name, value]...] | null},
      "response": {"status", "headers": [[name, value]...], "body": BODY, "source"},
      "client_ip", "consumer", "route", "upstream", "upstream_attempts",
      "timings": {"total_ms", "upstream_ms", "policies_ms"},
      "trace": [policy decision, ...],
      "started_at": epoch seconds
    }

    BODY = {"captured": bool, "size": int, "truncated": bool,
            "encoding": "utf-8" | "base64", "text": str}

It holds credentials as received, so it is stored only encrypted (AES-256-GCM with the secrets
box; the associated data binds the token to its tenant and capture session) and is masked for
display unless the viewer holds ``inspector:unmask``.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from apiedge.security.crypto import SecretBox


def exchange_aad(tenant_id: int, session_id: int) -> str:
    return f"tenant:{tenant_id}/capture:{session_id}/exchange"


def seal(box: SecretBox, tenant_id: int, session_id: int, data: dict[str, Any]) -> str:
    return box.encrypt(json.dumps(data, separators=(",", ":")), exchange_aad(tenant_id, session_id))


def unseal(box: SecretBox, tenant_id: int, session_id: int, token: str) -> dict[str, Any]:
    """Decrypt a stored exchange (raises ``DecryptionError`` if it does not belong here)."""
    value = json.loads(box.decrypt(token, exchange_aad(tenant_id, session_id)))
    if not isinstance(value, dict):
        raise ValueError("stored exchange is not an object")
    return value


def encode_body(data: bytes | None, total: int, limit: int) -> dict[str, Any]:
    """The stored form of a body: at most ``limit`` bytes, as text when it is UTF-8."""
    if data is None:
        return {"captured": False, "size": 0, "truncated": False, "encoding": "utf-8", "text": ""}
    part = data[: max(limit, 0)]
    truncated = total > len(part)
    text: str | None = None
    # A cut may split a multi-byte character: drop up to three trailing bytes before giving up.
    for trim in range(4 if truncated else 1):
        try:
            text = part[: len(part) - trim].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    if text is not None:
        return {
            "captured": True,
            "size": total,
            "truncated": truncated,
            "encoding": "utf-8",
            "text": text,
        }
    return {
        "captured": True,
        "size": total,
        "truncated": truncated,
        "encoding": "base64",
        "text": base64.b64encode(part).decode("ascii"),
    }


def decode_body(body: dict[str, Any]) -> bytes:
    text = str(body.get("text") or "")
    if body.get("encoding") == "base64":
        return base64.b64decode(text)
    return text.encode("utf-8")
