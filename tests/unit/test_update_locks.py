# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the lock generator's per-target marker logic (scripts/update-locks.py)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from packaging.markers import Marker
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "apiedge_update_locks", ROOT / "scripts" / "update-locks.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(mod)
    return mod


ul = _load()


def _targets(pred: object) -> set[object]:
    return {t for t in ul.TARGETS if pred(t)}  # type: ignore[operator]


def _selects_exactly(marker: str | None, targets: set[object]) -> bool:
    for t in ul.TARGETS:
        hit = marker is None or Marker(marker).evaluate(ul.marker_env(t))
        if hit != (t in targets):
            return False
    return True


def test_all_targets_need_no_marker() -> None:
    assert ul.render_marker(set(ul.TARGETS)) is None


def test_python_prefix_marker() -> None:
    sel = _targets(lambda t: t[1] == "3.10")
    marker = ul.render_marker(sel)
    assert marker == 'python_version < "3.11"'
    assert _selects_exactly(marker, sel)


def test_python_suffix_marker() -> None:
    sel = _targets(lambda t: t[1] != "3.10")
    marker = ul.render_marker(sel)
    assert marker == 'python_version >= "3.11"'
    assert _selects_exactly(marker, sel)


def test_windows_only_marker() -> None:
    sel = _targets(lambda t: t[0].sys_platform == "win32")
    marker = ul.render_marker(sel)
    assert marker == 'sys_platform == "win32"'
    assert _selects_exactly(marker, sel)


def test_mixed_marker_is_exact() -> None:
    sel = _targets(
        lambda t: t[0].machine == "aarch64" or (t[0].label == "win_amd64" and t[1] == "3.12")
    )
    assert _selects_exactly(ul.render_marker(sel), sel)


def test_graph_walk_evaluates_markers_and_extras_per_target() -> None:
    dists = {
        "app": ul.Dist(
            "app", "1", [Requirement("lib[x]"), Requirement('bp; python_version < "3.11"')]
        ),
        "lib": ul.Dist("lib", "1", [Requirement('opt; extra == "x"'), Requirement("base")]),
        "opt": ul.Dist("opt", "1", []),
        "base": ul.Dist("base", "1", []),
        "bp": ul.Dist("bp", "1", []),
    }
    win310 = next(t for t in ul.TARGETS if t[0].label == "win_amd64" and t[1] == "3.10")
    lin312 = next(t for t in ul.TARGETS if t[0].label == "linux_x86_64" and t[1] == "3.12")
    roots = [Requirement("app")]
    assert ul.needed_for(win310, roots, dists) == {"app", "lib", "opt", "base", "bp"}
    assert ul.needed_for(lin312, roots, dists) == {"app", "lib", "opt", "base"}


def test_committed_locks_have_markers_for_backports() -> None:
    text = (ROOT / "requirements" / "dev.lock").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.startswith("backports-asyncio-runner=="))
    assert 'python_version < "3.11"' in line


def test_full_version_boundaries_from_markers() -> None:
    markers = ['python_full_version < "3.11.3"', 'python_version < "3.11"', "extra == 'x'"]
    assert ul.full_version_boundaries(markers) == {"3.11.3"}
    assert ul.full_version_boundaries(['python_full_version <= "3.12.1"']) == {"3.12.2"}
    # boundaries at a minor start or outside the supported minors are not split points
    assert ul.full_version_boundaries(['python_full_version >= "3.11.0"']) == set()
    assert ul.full_version_boundaries(['python_full_version < "3.9.2"']) == set()


def test_python_full_version_marker_is_carried() -> None:
    """redis needs async-timeout for python_full_version < "3.11.3", not just < "3.11"."""
    try:
        ul.configure_pythons({"3.11.3"})
        assert ul.PY_POINTS == ("3.10", "3.11", "3.11.3", "3.12")
        dists = {
            "redis": ul.Dist(
                "redis", "1", [Requirement('async-timeout; python_full_version < "3.11.3"')]
            ),
            "async-timeout": ul.Dist("async-timeout", "1", []),
        }
        roots = [Requirement("redis")]
        sel = _targets(lambda t: "async-timeout" in ul.needed_for(t, roots, dists))
        marker = ul.render_marker(sel)
        assert marker == 'python_full_version < "3.11.3"'
        assert _selects_exactly(marker, sel)
        # whole-minor selections keep the readable python_version form
        assert ul.render_marker(_targets(lambda t: t[1] == "3.10")) == 'python_version < "3.11"'
        assert Marker(marker).evaluate({"python_full_version": "3.11.2", "python_version": "3.11"})
        assert not Marker(marker).evaluate(
            {"python_full_version": "3.11.3", "python_version": "3.11"}
        )
    finally:
        ul.configure_pythons(set())


def test_committed_locks_carry_full_version_marker_for_async_timeout() -> None:
    text = (ROOT / "requirements" / "runtime.lock").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.startswith("async-timeout=="))
    assert 'python_full_version < "3.11.3"' in line
