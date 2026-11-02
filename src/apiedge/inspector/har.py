# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""HAR 1.2 export of captured exchanges (T-012).

The caller passes exchanges that are already masked (or deliberately unmasked). APIEdge-specific
data (request id, policy trace, upstream, consumer) goes into ``_apiedge`` fields, which HAR
allows for custom data.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl

from apiedge import __version__


def _headers(items: Iterable[Any]) -> list[dict[str, str]]:
    return [{"name": str(i[0]), "value": str(i[1])} for i in items]


def _ctype(items: Iterable[Any]) -> str:
    for i in items:
        if str(i[0]).lower() == "content-type":
            return str(i[1])
    return ""


def entry(data: dict[str, Any], request_id: str) -> dict[str, Any]:
    req = data.get("request") or {}
    res = data.get("response") or {}
    req_headers = req.get("headers") or []
    res_headers = res.get("headers") or []
    req_body = req.get("body") or {}
    res_body = res.get("body") or {}
    timings = data.get("timings") or {}
    total = float(timings.get("total_ms") or 0.0)
    wait = timings.get("upstream_ms")
    wait_ms = float(wait) if wait is not None else total
    started = datetime.fromtimestamp(float(data.get("started_at") or 0), timezone.utc)
    request: dict[str, Any] = {
        "method": req.get("method", ""),
        "url": req.get("url", ""),
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": _headers(req_headers),
        "queryString": [
            {"name": k, "value": v}
            for k, v in parse_qsl(str(req.get("query") or ""), keep_blank_values=True)
        ],
        "headersSize": -1,
        "bodySize": int(req_body.get("size") or 0) if req_body.get("captured") else -1,
    }
    if req_body.get("captured") and req_body.get("size"):
        post: dict[str, Any] = {"mimeType": _ctype(req_headers), "text": req_body.get("text", "")}
        if req_body.get("encoding") == "base64":
            post["_encoding"] = "base64"
        request["postData"] = post
    content: dict[str, Any] = {
        "size": int(res_body.get("size") or 0),
        "mimeType": _ctype(res_headers),
        "text": res_body.get("text", ""),
    }
    if res_body.get("encoding") == "base64":
        content["encoding"] = "base64"
    return {
        "startedDateTime": started.isoformat().replace("+00:00", "Z"),
        "time": round(total, 3),
        "request": request,
        "response": {
            "status": int(res.get("status") or 0),
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _headers(res_headers),
            "content": content,
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": int(res_body.get("size") or 0),
        },
        "cache": {},
        "timings": {
            "send": 0,
            "wait": round(wait_ms, 3),
            "receive": round(max(total - wait_ms, 0.0), 3),
        },
        "_apiedge": {
            "request_id": request_id,
            "consumer": data.get("consumer", ""),
            "route": data.get("route", ""),
            "upstream": data.get("upstream", ""),
            "client_ip": data.get("client_ip", ""),
            "source": res.get("source", ""),
            "request_body_truncated": bool(req_body.get("truncated")),
            "response_body_truncated": bool(res_body.get("truncated")),
            "trace": data.get("trace") or [],
        },
    }


def har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "APIEdge", "version": __version__},
            "entries": entries,
        }
    }
