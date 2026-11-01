# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the stdlib-only one-click installer (scripts/install.py)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest
from platformdirs import user_data_path

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "apiedge_install", ROOT / "scripts" / "install.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


install = _load()


def test_data_dir_matches_platformdirs() -> None:
    assert install.default_data_dir() == user_data_path("APIEdge", appauthor="APIEdge")


def test_locks_exist_and_are_hashed() -> None:
    for name in ("runtime.lock", "dev.lock", "build.lock"):
        text = (ROOT / "requirements" / name).read_text(encoding="utf-8")
        pins = [ln for ln in text.splitlines() if "==" in ln]
        assert pins, name
        assert text.count("--hash=sha256:") >= len(pins), name


def test_shell_quoting() -> None:
    assert install._sh_quote("a'b") == "'a'\"'\"'b'"
    assert install._desktop_quote("/usr/bin/apiedge") == "/usr/bin/apiedge"
    assert install._desktop_quote('/x y/"$z`') == '"/x y/\\"\\$z\\`"'


def test_unsupported_python_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 9, 0, "final", 0))
    with pytest.raises(SystemExit) as exc:
        install.check_python()
    assert exc.value.code == 3


def test_uninstall_keeps_data_unless_purged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shortcut = tmp_path / "APIEdge.lnk"
    monkeypatch.setattr(install, "shortcut_paths", lambda: [shortcut])
    shortcut.write_text("x")
    venv_dir, data_dir = tmp_path / "venv", tmp_path / "data"
    venv_dir.mkdir()
    data_dir.mkdir()
    common = ["--yes", "--venv-dir", str(venv_dir), "--data-dir", str(data_dir)]
    assert install.main(["--uninstall", *common]) == 0
    assert not venv_dir.exists()
    assert not shortcut.exists()
    assert data_dir.exists()
    assert install.main(["--uninstall", "--purge-data", *common]) == 0
    assert not data_dir.exists()


def test_redact_hides_url_credentials() -> None:
    assert install.redact("--proxy http://bob:s3cret@proxy:3128") == "--proxy http://***@proxy:3128"
    assert install.redact("https://pypi.org/simple") == "https://pypi.org/simple"


def test_systemd_unit_quotes_paths() -> None:
    unit = install.systemd_unit(PurePosixPath("/opt/a b/apiedge"), ["--port", "9000"])
    assert 'ExecStart="/opt/a b/apiedge" run --no-migrate --port 9000' in unit
    assert "WantedBy=default.target" in unit


def test_launchd_plist_escapes_xml() -> None:
    plist = install.launchd_plist(
        PurePosixPath("/x/<&>/apiedge"), ["--data-dir", "/d"], PurePosixPath("/d")
    )
    assert "<string>/x/&lt;&amp;&gt;/apiedge</string>" in plist
    assert "<string>--no-migrate</string>" in plist


def test_secret_command_output_is_not_logged(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    log = install.open_log(tmp_path)
    try:
        install.run([sys.executable, "-c", "print('TOP' + 'SECRET')"], log_output=False)
        install.run([sys.executable, "-c", "print('visible-line')"])
    finally:
        install.close_log()
    text = log.read_text(encoding="utf-8")
    assert "TOPSECRET" not in text
    assert "output not logged" in text
    assert "visible-line" in text


def test_unattended_alias_and_network_options(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    seen: dict[str, argparse.Namespace] = {}

    def fake_uninstall(_v: Path, _d: Path, args: argparse.Namespace) -> int:
        seen["args"] = args
        return 0

    monkeypatch.setattr(install, "uninstall", fake_uninstall)
    install.main(
        ["--uninstall", "--unattended", "--proxy", "http://p:1", "--index-url", "https://m/s"]
    )
    args = seen["args"]
    assert args.yes is True
    assert args.proxy == "http://p:1"
    assert args.index_url == "https://m/s"
