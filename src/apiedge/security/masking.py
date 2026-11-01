# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Secret masking for logs (and later the packet inspector, T-012).

Two layers:

* **Key-based**: values whose key looks sensitive (``password``, ``token``, ``authorization``,
  ``cookie``, ``api_key``, ``secret`` ...) are replaced by :data:`MASK`, recursively through
  dicts, lists and tuples.
* **Pattern-based**: free text is scrubbed of bearer/basic credentials, ``key=value`` pairs with a
  sensitive key, JWTs and PEM private keys.

Masking is deliberately over-eager: a false positive costs a log detail, a false negative leaks a
credential.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MASK = "***"

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|authori[sz]ation|cookie|session|"
    r"api[-_]?key|apikey|private[-_]?key|credential|signature|otp|totp|csrf)",
    re.IGNORECASE,
)

_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM private keys
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        MASK,
    ),
    # Authorization schemes
    (
        re.compile(r"\b(Bearer|Basic|Digest|ApiKey)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
        r"\1 " + MASK,
    ),
    # JWT / JWS compact serialisation
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), MASK),
    # key=value / key: value / "key": "value" with a sensitive key
    (
        re.compile(
            r"""(?P<k>["']?[\w.-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|"""
            r"""authori[sz]ation|cookie|session|credential)[\w.-]*["']?\s*[=:]\s*)"""
            r"""(?P<v>"[^"]*"|'[^']*'|[^\s,;&}]+)""",
            re.IGNORECASE,
        ),
        r"\g<k>" + MASK,
    ),
)


def is_sensitive_key(key: str) -> bool:
    """True if a field/header/parameter name should never be logged in clear."""
    return bool(_SENSITIVE_KEY.search(key))


def mask_text(text: str) -> str:
    """Scrub credentials embedded in free text."""
    for pattern, repl in _TEXT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def mask_value(value: Any, *, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with sensitive keys masked and strings scrubbed."""
    if _depth > 20:  # defensive bound on pathological nesting
        return MASK
    if isinstance(value, Mapping):
        return {
            k: (
                MASK
                if isinstance(k, str) and is_sensitive_key(k)
                else mask_value(v, _depth=_depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(mask_value(v, _depth=_depth + 1) for v in value)
    if isinstance(value, str):
        return mask_text(value)
    return value
