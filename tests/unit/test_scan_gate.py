# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the ZAP / Grype scan gate (scripts/scan-gate.py) and the DAST smoke script."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
TODAY = dt.date(2026, 11, 2)


def _load(name: str, file: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load("apiedge_scan_gate", "scan-gate.py")

DOC = """
### Accepted scanner findings

| Scanner | ID | Target | Justification | Accepted | Review by |
|---|---|---|---|---|---|
| zap | `10038` | console | reviewed | 2026-11-01 | 2027-01-31 |
| grype | CVE-2026-0001 | libfoo | no fix, not reachable | 2026-11-01 | 2027-02-01 |

## Next section
| not | part |
"""

ZAP = {
    "site": [
        {
            "alerts": [
                {"pluginid": "10038", "alert": "CSP", "riskcode": "2", "riskdesc": "Medium"},
                {"pluginid": "10020", "alert": "Frame", "riskcode": "2", "riskdesc": "Medium"},
                {"pluginid": "10049", "alert": "Cacheable", "riskcode": "0", "riskdesc": "Info"},
            ]
        }
    ]
}


def _grype(vid: str, pkg: str, severity: str) -> dict[str, object]:
    return {
        "vulnerability": {"id": vid, "severity": severity, "fix": {"versions": []}},
        "artifact": {"name": pkg, "version": "1.0", "type": "deb"},
    }


def test_table_parsing_stops_at_the_table() -> None:
    rows = gate.parse_table(DOC)
    assert [(r.scanner, r.id, r.target) for r in rows] == [
        ("zap", "10038", "console"),
        ("grype", "CVE-2026-0001", "libfoo"),
    ]
    assert gate.check_rows(rows, TODAY) == []


def test_rows_need_dates_justification_and_timely_review() -> None:
    bad = [
        gate.Row("zap", "1", "console", "", "2026-11-01", "2026-12-01"),
        gate.Row("zap", "2", "console", "ok", "2026-01-01", "2026-12-31"),  # > 180 days
        gate.Row("zap", "3", "console", "ok", "2026-09-01", "2026-10-01"),  # expired
        gate.Row("nmap", "4", "x", "ok", "2026-11-01", "2026-12-01"),
        gate.Row("zap", "5", "console", "ok", "soon", "later"),
    ]
    errors = gate.check_rows(bad, TODAY)
    assert any("incomplete" in e for e in errors)
    assert any("within 180 days" in e for e in errors)
    assert any("past its review date" in e for e in errors)
    assert any("unknown scanner" in e for e in errors)
    assert any("YYYY-MM-DD" in e for e in errors)


def test_zap_medium_alerts_fail_unless_accepted_for_that_target() -> None:
    rows = gate.parse_table(DOC)
    errors = gate.gate("zap", gate.zap_findings(ZAP, "console"), rows)
    assert len(errors) == 1 and "10020" in errors[0]
    # The acceptance is per target: the same alert on the gateway is not accepted.
    errors = gate.gate("zap", gate.zap_findings(ZAP, "gateway"), rows)
    assert len(errors) == 2


def test_grype_high_and_critical_fail_unless_accepted() -> None:
    rows = gate.parse_table(DOC)
    report = {
        "matches": [
            _grype("CVE-2026-0001", "libfoo", "Critical"),  # accepted
            _grype("CVE-2026-0002", "libbar", "High"),
            _grype("CVE-2026-0003", "libbaz", "Medium"),
            _grype("CVE-2026-0001", "libother", "Critical"),  # same id, other package
        ]
    }
    errors = gate.gate("grype", gate.grype_findings(report), rows)
    assert sorted(e.split()[2] for e in errors) == ["CVE-2026-0001", "CVE-2026-0002"]


def test_main_check_and_report_modes(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "SECURITY.md").write_text(DOC, encoding="utf-8")
    report = tmp_path / "zap.json"
    report.write_text(json.dumps(ZAP), encoding="utf-8")
    common = ["--root", str(tmp_path), "--today", "2026-11-02"]
    assert gate.main(["check", *common]) == 0
    assert gate.main(["zap", "--report", str(report), "--target", "console", *common]) == 1
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"matches": []}), encoding="utf-8")
    assert gate.main(["grype", "--report", str(clean), *common]) == 0
    assert gate.main(["check", "--root", str(tmp_path), "--today", "2027-03-01"]) == 1


def test_repository_table_is_valid() -> None:
    rows = gate.parse_table((ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8"))
    assert gate.check_rows(rows, dt.date.today()) == []


def test_dast_smoke_leak_detection() -> None:
    dast = _load("apiedge_dast_smoke", "dast-smoke.py")
    leaky = dast.Response(500, None, b'Traceback (most recent call last):\n  File "x.py"')
    clean = dast.Response(500, None, b'{"detail":"Internal Server Error","request_id":"abc"}')
    assert not dast.no_leak(leaky)
    assert dast.no_leak(clean)
