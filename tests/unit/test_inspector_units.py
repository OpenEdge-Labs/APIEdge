# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Packet inspector units (T-012): body encoding, masking, HAR, the recorder's matching and
its memory bound."""

from __future__ import annotations

import json
import time
from typing import Any

from apiedge.inspector.har import entry, har
from apiedge.inspector.masking import Masker
from apiedge.inspector.recorder import ActiveCapture, CaptureRecorder, PendingExchange
from apiedge.inspector.store import decode_body, encode_body, seal, unseal
from apiedge.policies.base import GatewayResponse, RequestContext
from apiedge.security.crypto import DecryptionError, SecretBox


def test_encode_body_text_binary_truncation() -> None:
    assert encode_body(None, 0, 10)["captured"] is False
    b = encode_body(b"hello world", 11, 5)
    assert b["text"] == "hello" and b["truncated"] and b["size"] == 11
    # A cut inside a multi-byte character keeps the text readable.
    euro = "a€".encode()  # 1 + 3 bytes
    cut = encode_body(euro, 4, 3)
    assert cut["encoding"] == "utf-8" and cut["text"] == "a" and cut["truncated"]
    binary = encode_body(b"\xff\xfe\x00", 3, 10)
    assert binary["encoding"] == "base64" and decode_body(binary) == b"\xff\xfe\x00"
    assert decode_body(encode_body(b"x" * 3, 3, 0)) == b""


def test_seal_is_bound_to_tenant_and_session() -> None:
    box = SecretBox([b"k" * 32])
    token = seal(box, 1, 2, {"a": 1})
    assert unseal(box, 1, 2, token) == {"a": 1}
    for tenant, session in ((2, 2), (1, 3)):
        try:
            unseal(box, tenant, session, token)
        except DecryptionError:
            continue
        raise AssertionError("token decrypted under another tenant/session")


_BODY = json.dumps({"password": "p", "card": {"ssn": "1", "ok": "Bearer zzz"}}).encode()


def _exchange() -> dict[str, Any]:
    return {
        "request": {
            "method": "POST",
            "url": "http://gw/acme/x?api_key=k1&page=2&ssn=9",
            "query": "api_key=k1&page=2",
            "headers": [
                ["authorization", "Bearer abc.def"],
                ["cookie", "sid=1"],
                ["x-api-key", "k2"],
                ["x-client-ref", "ref-7"],
                ["content-type", "application/json"],
                ["accept", "*/*"],
            ],
            "body": encode_body(_BODY, len(_BODY), 1000),
            "upstream_headers": [["x-forwarded-token", "t"]],
            "upstream_query": "page=2",
        },
        "response": {
            "status": 200,
            "headers": [["set-cookie", "s=1"], ["content-type", "text/plain"]],
            "body": encode_body(b"token=abc ok", 12, 1000),
            "source": "upstream",
        },
        "trace": [{"policy_id": "p", "detail": "Authorization: Bearer abc"}],
        "timings": {"total_ms": 12.5, "upstream_ms": 10.0},
        "started_at": 1_700_000_000.0,
    }


def test_masker_masks_everything_sensitive() -> None:
    data = _exchange()
    out = Masker(["SSN", "x-client-ref"]).exchange(data)
    assert data["request"]["headers"][0][1] == "Bearer abc.def"  # input untouched
    headers = dict(out["request"]["headers"])
    assert headers["authorization"] == headers["cookie"] == headers["x-api-key"] == "***"
    assert headers["x-client-ref"] == "***" and headers["accept"] == "*/*"
    assert "k1" not in out["request"]["url"] and "ssn=%2A%2A%2A" in out["request"]["url"]
    assert "page=2" in out["request"]["query"] and "k1" not in out["request"]["query"]
    body = json.loads(out["request"]["body"]["text"])
    assert body == {"password": "***", "card": {"ssn": "***", "ok": "Bearer ***"}}
    assert dict(out["request"]["upstream_headers"])["x-forwarded-token"] == "***"
    assert dict(out["response"]["headers"])["set-cookie"] == "***"
    assert "abc" not in out["response"]["body"]["text"]
    assert "abc" not in out["trace"][0]["detail"]


def test_masker_form_and_truncated_json() -> None:
    m = Masker(["pin"])
    form = m.body(
        encode_body(b"user=a&password=b&pin=1", 23, 100), "application/x-www-form-urlencoded"
    )
    assert "b" not in form["text"].split("password=")[1].split("&")[0]
    assert "pin=%2A%2A%2A" in form["text"]
    cut = m.body(encode_body(b'{"pin": "1234", "password": "x", "more', 50, 37), "application/json")
    assert "1234" not in cut["text"] and '"x"' not in cut["text"]
    raw = {"captured": True, "encoding": "base64", "text": "AAA=", "size": 2, "truncated": False}
    assert m.body(raw, "application/octet-stream") == raw


def test_har_entry() -> None:
    doc = har([entry(_exchange(), "rid-1")])
    log = doc["log"]
    assert log["version"] == "1.2" and log["creator"]["name"] == "APIEdge"
    e = log["entries"][0]
    assert e["startedDateTime"].endswith("Z") and e["time"] == 12.5
    assert e["timings"] == {"send": 0, "wait": 10.0, "receive": 2.5}
    assert e["request"]["postData"]["mimeType"] == "application/json"
    assert {"name": "page", "value": "2"} in e["request"]["queryString"]
    assert e["response"]["content"]["mimeType"] == "text/plain"
    assert e["_apiedge"]["request_id"] == "rid-1"


def _ctx(**kw: Any) -> RequestContext:
    base: dict[str, Any] = {
        "method": "GET",
        "path": "/x",
        "route": "/x",
        "query": [],
        "raw_query": "",
        "headers": [],
        "client_ip": "203.0.113.1",
        "request_id": "r",
        "tenant_id": 1,
        "api_id": 7,
        "url": "http://gw/acme/api/x",
        "started_at": time.time(),
    }
    base.update(kw)
    return RequestContext(**base)


def _capture(**kw: Any) -> ActiveCapture:
    base: dict[str, Any] = {
        "id": 1,
        "tenant_id": 1,
        "product_id": 3,
        "api_id": 7,
        "route": None,
        "consumer": None,
        "expires_at": time.time() + 60,
        "max_body": 4,
    }
    base.update(kw)
    return ActiveCapture(**base)


def test_capture_matching() -> None:
    now = time.time()
    ctx = _ctx()
    assert _capture().matches(ctx, now)
    assert not _capture(expires_at=now - 1).matches(ctx, now)  # time box
    assert not _capture(tenant_id=2).matches(ctx, now)  # never another tenant's traffic
    assert not _capture(api_id=8).matches(ctx, now)
    assert not _capture(route="/y").matches(ctx, now)
    assert _capture(route="/x").matches(ctx, now)
    assert not _capture(consumer="key:a").matches(ctx, now)
    assert _capture(consumer="").matches(ctx, now)  # anonymous


def test_recorder_tap_and_memory_bound() -> None:
    rec = CaptureRecorder(queue_max_bytes=3000)
    rec._by_api = {7: [_capture()]}
    assert rec.listener(_ctx(api_id=9), GatewayResponse(200)) is None
    tap = rec.listener(_ctx(), GatewayResponse(200, [("content-type", "text/plain")]))
    assert tap is not None
    tap.body_chunk(b"abcdef")
    tap.body_chunk(b"ghi")
    tap.finish(9)
    item: PendingExchange = rec._pending[0]
    body = item.data["response"]["body"]
    assert body["text"] == "abcd" and body["truncated"] and body["size"] == 9
    assert item.data["request"]["body"]["captured"] is False  # never read by the gateway
    # The queue is bounded in bytes: further exchanges are dropped and counted.
    for _ in range(5):
        t = rec.listener(_ctx(), GatewayResponse(200))
        assert t is not None
        t.finish(0)
    assert len(rec._pending) == 2 and rec.dropped == 4
