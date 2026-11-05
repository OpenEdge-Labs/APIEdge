# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Structured logging (T-002, OWASP A09).

Every record is emitted as one JSON object per line (``APIEDGE_LOG_FORMAT=json``, the default) or as
a readable text line (``text``, for development). Messages, exception text and ``extra`` fields are
passed through :mod:`apiedge.security.masking`, so credentials never reach the log sink. The current
request id (see :mod:`apiedge.security.middleware`) is attached to every record.
"""

from __future__ import annotations

import json
import logging
import logging.config
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from apiedge.security.masking import mask_text, mask_value

request_id_var: ContextVar[str | None] = ContextVar("apiedge_request_id", default=None)

# Attributes every LogRecord has; anything else was passed through ``extra=``.
_STD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
    | {"message", "asctime", "taskName"}
)


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {k: v for k, v in vars(record).items() if k not in _STD_ATTRS and not k.startswith("_")}


class JsonFormatter(logging.Formatter):
    """One masked JSON object per record."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": mask_text(record.getMessage()),
        }
        rid = request_id_var.get()
        if rid:
            entry["request_id"] = rid
        extras = _extras(record)
        if extras:
            entry.update(mask_value(extras))
        if record.exc_info:
            entry["exc"] = mask_text(self.formatException(record.exc_info))
        return json.dumps(entry, default=str, ensure_ascii=False)


class MaskingTextFormatter(logging.Formatter):
    """Human-readable formatter that applies the same masking."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = mask_text(super().format(record))
        extras = _extras(record)
        if extras:
            line += " " + json.dumps(mask_value(extras), default=str, ensure_ascii=False)
        rid = request_id_var.get()
        return f"{line} [rid={rid}]" if rid else line


def logging_config(level: str = "info", fmt: str = "json") -> dict[str, Any]:
    """``logging.config.dictConfig`` dict; also handed to uvicorn so its logs are masked too."""
    formatter = "json" if fmt == "json" else "text"
    lvl = level.upper()
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": JsonFormatter},
            "text": {"()": MaskingTextFormatter},
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": formatter,
                "stream": "ext://sys.stderr",
            }
        },
        "root": {"handlers": ["default"], "level": lvl},
        "loggers": {
            "uvicorn": {"handlers": [], "level": lvl, "propagate": True},
            "uvicorn.error": {"handlers": [], "level": lvl, "propagate": True},
            # Our own access log (apiedge.access) replaces uvicorn's, which logs raw query strings.
            "uvicorn.access": {"handlers": [], "level": "WARNING", "propagate": False},
        },
    }


def configure_logging(level: str = "info", fmt: str = "json") -> None:
    logging.config.dictConfig(logging_config(level, fmt))
