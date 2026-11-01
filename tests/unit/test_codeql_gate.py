# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the CodeQL acceptance gate (scripts/codeql-gate.py)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
RULE = "py/clear-text-logging-sensitive-data"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "apiedge_codeql_gate", ROOT / "scripts" / "codeql-gate.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(mod)
    return mod


gate = _load()

DOC_HEAD = (
    "# Security\n\n### Accepted findings\n\n"
    "| File | Rule | Justification | Date |\n|---|---|---|---|\n"
)


def _repo(tmp: Path, source: str, rows: str) -> Path:
    (tmp / "src" / "pkg").mkdir(parents=True)
    (tmp / "src" / "pkg" / "a.py").write_text(source, encoding="utf-8")
    (tmp / "docs").mkdir()
    (tmp / "docs" / "SECURITY.md").write_text(DOC_HEAD + rows + "\n## Next\n", encoding="utf-8")
    return tmp


def _row(file: str = "src/pkg/a.py", rule: str = RULE, date: str = "2026-11-01") -> str:
    return f"| `{file}` | `{rule}` | shown once by design | {date} |\n"


def _sarif(tmp: Path, uri: str, line: int, rule: str = RULE) -> Path:
    d = tmp / "sarif"
    d.mkdir()
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
    result = {"ruleId": rule, "level": "error", "message": {"text": "x"}, "locations": [loc]}
    (d / "python.sarif").write_text(json.dumps({"runs": [{"results": [result]}]}))
    return d


MARKED = f"x = 1\nprint(pw)  # codeql[{RULE}] shown once\n"


def test_repository_is_consistent() -> None:
    assert gate.main(["--root", str(ROOT)]) == 0


def test_marker_and_row_accept_finding(tmp_path: Path) -> None:
    root = _repo(tmp_path, MARKED, _row())
    sarif = _sarif(tmp_path, "src/pkg/a.py", 2)
    assert gate.main(["--root", str(root), "--sarif-dir", str(sarif)]) == 0


def test_marker_without_row_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, MARKED, "")
    assert gate.main(["--root", str(root)]) == 1


def test_row_without_marker_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, "print(pw)\n", _row())
    assert gate.main(["--root", str(root)]) == 1


def test_row_needs_iso_date(tmp_path: Path) -> None:
    root = _repo(tmp_path, MARKED, _row(date="soon"))
    assert gate.main(["--root", str(root)]) == 1


def test_marker_needs_reason(tmp_path: Path) -> None:
    root = _repo(tmp_path, f"print(pw)  # codeql[{RULE}]\n", _row())
    assert gate.main(["--root", str(root)]) == 1


def test_finding_without_marker_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, MARKED, _row())
    sarif = _sarif(tmp_path, "src/pkg/a.py", 1)  # line 1 carries no marker
    assert gate.main(["--root", str(root), "--sarif-dir", str(sarif)]) == 1


def test_marker_for_other_rule_does_not_accept(tmp_path: Path) -> None:
    root = _repo(tmp_path, MARKED, _row())
    sarif = _sarif(tmp_path, "src/pkg/a.py", 2, rule="py/other-rule")
    assert gate.main(["--root", str(root), "--sarif-dir", str(sarif)]) == 1


def test_parse_table_stops_at_next_section() -> None:
    rows = gate.parse_table(DOC_HEAD + _row() + "\n## Next\n\n| `x` | `y` | z | 2026-01-01 |\n")
    assert [(r.file, r.rule) for r in rows] == [("src/pkg/a.py", RULE)]
