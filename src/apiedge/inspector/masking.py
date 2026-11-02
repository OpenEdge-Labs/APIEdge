# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Masking of captured exchanges for display (T-012, ADR 0010).

Masked by default, everywhere an exchange leaves the server (detail view, live view, HAR export,
replay results):

* headers: ``Authorization``, ``Proxy-Authorization``, ``Cookie``, ``Set-Cookie`` and every
  header whose name looks sensitive (API keys, tokens, secrets, sessions ...);
* query and form parameters with a sensitive name;
* JSON bodies: values of sensitive keys at any depth, and credentials embedded in strings;
* other text bodies and policy-trace details: embedded credentials (bearer/basic tokens, JWTs,
  ``key=value`` pairs with a sensitive key, PEM private keys);
* in all of the above, the names configured per capture session and in
  ``APIEDGE_INSPECTOR_MASK_FIELDS`` (case-insensitive exact match).

Binary (base64) bodies are not inspected. Unmasked viewing needs ``inspector:unmask`` and is
audit-logged by the admin API.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from apiedge.security.masking import MASK, is_sensitive_key, mask_text

ALWAYS_MASKED_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
)
_MAX_DEPTH = 32


class Masker:
    def __init__(self, extra: Iterable[str] = ()) -> None:
        self.extra = frozenset(n.strip().lower() for n in extra if n.strip())
        self._named: re.Pattern[str] | None = None
        if self.extra:
            names = "|".join(re.escape(n) for n in sorted(self.extra))
            # "name": value (JSON, also when embedded in a string) and name=value pairs.
            self._named = re.compile(
                r'(?P<k>"(?i:' + names + r')"\s*:\s*)(?P<v>"(?:[^"\\]|\\.)*"|[^\s,}\]]+)'
                r"|(?P<k2>\b(?i:" + names + r")=)(?P<v2>[^\s&;,]+)"
            )

    def text(self, text: str) -> str:
        """Scrub credentials and configured ``name: value`` / ``name=value`` pairs from text."""
        text = mask_text(text)
        if self._named is not None:
            text = self._named.sub(_named_repl, text)
        return text

    def sensitive(self, name: str) -> bool:
        low = name.lower()
        return low in ALWAYS_MASKED_HEADERS or low in self.extra or is_sensitive_key(name)

    def headers(self, headers: Iterable[Any]) -> list[list[str]]:
        out = []
        for item in headers:
            name, value = str(item[0]), str(item[1])
            out.append([name, MASK if self.sensitive(name) else self.text(value)])
        return out

    def query(self, query: str) -> str:
        if not query:
            return query
        pairs = parse_qsl(query, keep_blank_values=True)
        return urlencode([(k, MASK if self.sensitive(k) else self.text(v)) for k, v in pairs])

    def url(self, url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit(parts._replace(query=self.query(parts.query)))

    def value(self, value: Any, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            return MASK
        if isinstance(value, dict):
            return {
                k: MASK if self.sensitive(str(k)) else self.value(v, depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.value(v, depth + 1) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def body(self, body: dict[str, Any], content_type: str) -> dict[str, Any]:
        out = dict(body)
        if body.get("encoding") != "utf-8" or not body.get("text"):
            return out
        text = str(body["text"])
        ctype = content_type.split(";", 1)[0].strip().lower()
        if "json" in ctype and not body.get("truncated"):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            else:
                out["text"] = json.dumps(self.value(parsed), ensure_ascii=False)
                return out
        if ctype == "application/x-www-form-urlencoded":
            out["text"] = self.query(text)
            return out
        out["text"] = self.text(text)
        return out

    def exchange(self, data: dict[str, Any]) -> dict[str, Any]:
        """A masked deep copy of a stored exchange."""
        out = copy.deepcopy(data)
        req = out.get("request") or {}
        res = out.get("response") or {}
        req_ct = _header(req.get("headers") or [], "content-type")
        res_ct = _header(res.get("headers") or [], "content-type")
        if "url" in req:
            req["url"] = self.url(str(req["url"]))
        for key in ("query", "upstream_query"):
            if req.get(key):
                req[key] = self.query(str(req[key]))
        for key in ("headers", "upstream_headers"):
            if req.get(key) is not None:
                req[key] = self.headers(req[key])
        if isinstance(req.get("body"), dict):
            req["body"] = self.body(req["body"], req_ct)
        if res.get("headers") is not None:
            res["headers"] = self.headers(res["headers"])
        if isinstance(res.get("body"), dict):
            res["body"] = self.body(res["body"], res_ct)
        for entry in out.get("trace") or []:
            if isinstance(entry, dict) and isinstance(entry.get("detail"), str):
                entry["detail"] = self.text(entry["detail"])
        return out


def _header(headers: Iterable[Any], name: str) -> str:
    for item in headers:
        if str(item[0]).lower() == name:
            return str(item[1])
    return ""


def _named_repl(m: re.Match[str]) -> str:
    if m.group("k") is not None:
        return m.group("k") + json.dumps(MASK)
    return m.group("k2") + MASK
