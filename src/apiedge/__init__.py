# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""APIEdge: an on-premise, multi-tenant API Gateway with a no-code / low-code console."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("apiedge")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
