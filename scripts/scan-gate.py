# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Gate for dynamic (ZAP) and container image (Grype) scan results (T-018). Standard library only.

A finding at or above the threshold fails the build unless it is accepted by a row in the
"Accepted scanner findings" table of ``docs/SECURITY.md``:

    | Scanner | ID | Target | Justification | Accepted | Review by |

* ``Scanner`` is ``zap`` or ``grype``.
* ``ID`` is the ZAP plugin id (for example ``10038``) or the vulnerability id (``CVE-...`` /
  ``GHSA-...``).
* ``Target`` is the scanned surface for ZAP (``console`` or ``gateway``) or the package name for
  Grype (for example ``libssl3``).
* ``Accepted`` and ``Review by`` are ``YYYY-MM-DD``. A row past its review date fails the gate,
  so every acceptance is re-reviewed; at most 180 days between the two dates.

Thresholds: ZAP fails on Medium and High risk alerts (ZAP has no Critical); Grype fails on High
and Critical vulnerabilities. Lower findings are listed, not failed.

Usage::

    python scripts/scan-gate.py check                      # table only (CI quality job)
    python scripts/scan-gate.py zap --target console --report zap-console.json
    python scripts/scan-gate.py grype --report grype.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SECURITY_DOC = Path("docs") / "SECURITY.md"
TABLE_HEADING = re.compile(r"^#{2,6}\s.*\bAccepted scanner findings\b", re.IGNORECASE)
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SCANNERS = ("zap", "grype")
MAX_ACCEPT_DAYS = 180
ZAP_FAIL_RISK = 2  # 0 informational, 1 low, 2 medium, 3 high
GRYPE_FAIL = frozenset({"high", "critical"})


@dataclass(frozen=True)
class Row:
    scanner: str
    id: str
    target: str
    justification: str
    accepted: str
    review_by: str


@dataclass(frozen=True)
class Finding:
    id: str
    target: str
    severity: str
    title: str
    blocking: bool


def _cell(raw: str) -> str:
    cell = raw.strip()
    if len(cell) > 1 and cell[0] == "`" and cell[-1] == "`":
        cell = cell[1:-1].strip()
    return cell


def parse_table(doc_text: str) -> list[Row]:
    """Rows of the first markdown table after the "Accepted scanner findings" heading."""
    rows: list[Row] = []
    in_section = in_table = False
    for line in doc_text.splitlines():
        if not in_section:
            in_section = bool(TABLE_HEADING.match(line))
            continue
        stripped = line.strip()
        if stripped.startswith("|"):
            in_table = True
            cells = [_cell(c) for c in stripped.strip("|").split("|")]
            if cells and cells[0].lower() == "scanner":
                continue
            if all(set(c) <= set("-: ") for c in cells):
                continue
            cells += [""] * (6 - len(cells))
            rows.append(Row(cells[0].lower(), *cells[1:6]))
        elif in_table or stripped.startswith("#"):
            break
    return rows


def check_rows(rows: list[Row], today: dt.date) -> list[str]:
    errors: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        key = (r.scanner, r.id, r.target)
        name = f"{r.scanner} {r.id} {r.target}"
        if key in seen:
            errors.append(f"accepted scanner findings: duplicate row {name}")
        seen.add(key)
        if r.scanner not in SCANNERS:
            errors.append(f"accepted scanner findings: unknown scanner in row {name}")
        if not (r.id and r.target and r.justification):
            errors.append(f"accepted scanner findings: incomplete row {name}")
        if not (DATE.match(r.accepted) and DATE.match(r.review_by)):
            errors.append(f"accepted scanner findings: row {name} needs YYYY-MM-DD dates")
            continue
        accepted = dt.date.fromisoformat(r.accepted)
        review = dt.date.fromisoformat(r.review_by)
        if not accepted <= review <= accepted + dt.timedelta(days=MAX_ACCEPT_DAYS):
            errors.append(
                f"accepted scanner findings: row {name} must be reviewed within "
                f"{MAX_ACCEPT_DAYS} days of acceptance"
            )
        if review < today:
            errors.append(f"accepted scanner findings: row {name} is past its review date")
    return errors


def zap_findings(report: dict[str, Any], target: str) -> list[Finding]:
    out: list[Finding] = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            out.append(
                Finding(
                    id=str(alert.get("pluginid", "")),
                    target=target,
                    severity=str(alert.get("riskdesc", risk)),
                    title=str(alert.get("alert") or alert.get("name") or ""),
                    blocking=risk >= ZAP_FAIL_RISK,
                )
            )
    return out


def grype_findings(report: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for match in report.get("matches", []):
        vuln = match.get("vulnerability", {})
        art = match.get("artifact", {})
        severity = str(vuln.get("severity", "Unknown"))
        fix = ",".join(vuln.get("fix", {}).get("versions", [])) or "no fix"
        out.append(
            Finding(
                id=str(vuln.get("id", "")),
                target=str(art.get("name", "")),
                severity=severity,
                title=f"{art.get('name')} {art.get('version')} ({art.get('type')}), fix: {fix}",
                blocking=severity.lower() in GRYPE_FAIL,
            )
        )
    return out


def gate(scanner: str, findings: list[Finding], rows: list[Row]) -> list[str]:
    accepted = {(r.id, r.target) for r in rows if r.scanner == scanner}
    errors: list[str] = []
    for f in sorted(set(findings), key=lambda f: (not f.blocking, f.id, f.target)):
        where = f"{scanner} {f.id} [{f.severity}] {f.target}: {f.title}"
        if (f.id, f.target) in accepted:
            print(f"accepted (docs/SECURITY.md): {where}")
        elif f.blocking:
            print(f"::error::{where}")
            errors.append(f"FINDING {where}")
        else:
            print(f"below threshold (listed, not failed): {where}")
    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    p.add_argument("mode", choices=("check", *SCANNERS))
    p.add_argument("--report", type=Path)
    p.add_argument("--target", default="console", help="ZAP target name (console or gateway)")
    p.add_argument("--root", type=Path, default=Path())
    p.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    args = p.parse_args(argv)

    rows = parse_table((args.root / SECURITY_DOC).read_text(encoding="utf-8"))
    errors = check_rows(rows, args.today)
    if args.mode != "check":
        if args.report is None:
            p.error("--report is required")
        report = json.loads(args.report.read_text(encoding="utf-8"))
        found = zap_findings(report, args.target) if args.mode == "zap" else grype_findings(report)
        errors += gate(args.mode, found, rows)
        print(f"{args.mode}: {len(found)} finding(s) reported")
    for e in errors:
        print(e)
    print(f"scan gate: {len(rows)} accepted row(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
