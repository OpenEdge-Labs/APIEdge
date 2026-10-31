# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from apiedge.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Isolated settings: a fresh SQLite database in a temp data dir."""
    return Settings(data_dir=tmp_path / "data", env="production")
