# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import logging

import pytest

from apiedge.logs import JsonFormatter, MaskingTextFormatter, request_id_var
from apiedge.security.masking import MASK, is_sensitive_key, mask_text, mask_value

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer abc.def-ghi",
        "auth Basic dXNlcjpwYXNz",
        f"token {JWT}",
        "password=hunter2&user=bob",
        '{"client_secret": "xyz123"}',
        "api_key: k-123",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_mask_text_removes_credentials(text: str) -> None:
    out = mask_text(text)
    for secret in ("abc.def-ghi", "dXNlcjpwYXNz", JWT, "hunter2", "xyz123", "k-123", "MIIabc"):
        assert secret not in out
    assert MASK in out


def test_mask_text_keeps_ordinary_text() -> None:
    assert mask_text("GET /api/v1/products user=bob status=200") == (
        "GET /api/v1/products user=bob status=200"
    )


def test_mask_value_recursive() -> None:
    data = {
        "username": "bob",
        "Password": "p",
        "headers": {"Authorization": "Bearer x", "Accept": "json"},
        "items": [{"apiKey": "k"}, "Bearer tok"],
    }
    assert mask_value(data) == {
        "username": "bob",
        "Password": MASK,
        "headers": {"Authorization": MASK, "Accept": "json"},
        "items": [{"apiKey": MASK}, f"Bearer {MASK}"],
    }
    assert is_sensitive_key("X-API-Key") and is_sensitive_key("set-cookie")
    assert not is_sensitive_key("username")


def _record(msg: str, **extra: object) -> logging.LogRecord:
    rec = logging.LogRecord("apiedge.test", logging.INFO, __file__, 1, msg, None, None)
    for k, v in extra.items():
        setattr(rec, k, v)
    return rec


def test_json_formatter_masks_and_adds_request_id() -> None:
    token = request_id_var.set("rid-1")
    try:
        line = JsonFormatter().format(
            _record("login password=hunter2", user="bob", token="t0k", nested={"secret": "s"})
        )
    finally:
        request_id_var.reset(token)
    entry = json.loads(line)
    assert entry["level"] == "info" and entry["logger"] == "apiedge.test"
    assert entry["request_id"] == "rid-1"
    assert entry["user"] == "bob"
    assert entry["token"] == MASK and entry["nested"] == {"secret": MASK}
    assert "hunter2" not in line and "t0k" not in line


def test_json_formatter_masks_exceptions() -> None:
    try:
        raise ValueError("bad password=hunter2")
    except ValueError:
        import sys

        rec = _record("boom")
        rec.exc_info = sys.exc_info()
    entry = json.loads(JsonFormatter().format(rec))
    assert "ValueError" in entry["exc"] and "hunter2" not in entry["exc"]


def test_text_formatter_masks() -> None:
    out = MaskingTextFormatter().format(_record("Bearer abc", api_key="k1"))
    assert "abc" not in out and "k1" not in out
