# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""CodeQL acceptance gate (T-002). Standard library only.

A CodeQL finding may be accepted only when BOTH of these exist:

1. an inline justification comment on the flagged line, in the form used by GitHub code
   scanning: a ``#`` or ``//`` comment holding ``codeql[RULE-ID]`` followed by a reason;
2. a row for the same file and rule in the "Accepted findings" table of ``docs/SECURITY.md``
   with the columns File | Rule | Justification | Date (``YYYY-MM-DD``).

The gate fails when an inline marker has no table row, when a table row has no inline marker,
when a row is incomplete, or (given ``--sarif-dir``) when any error- or warning-level SARIF
result is not accepted by both.

Usage: ``python scripts/codeql-gate.py [--sarif-dir sarif-results] [--root .]``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

SCAN_ROOTS = ("src", "scripts", "console")
SCAN_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})
SKIP_DIRS = frozenset({"node_modules", "static", "dist", "build", "__pycache__", ".venv"})
SECURITY_DOC = Path("docs") / "SECURITY.md"
TABLE_HEADING = re.compile(r"^#{2,6}\s.*\bAccepted findings\b", re.IGNORECASE)
MARKER = re.compile(r"(?:#|//)\s*codeql\[(?P<rule>[A-Za-z0-9_./-]+)\](?P<reason>[^\n]*)")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class Marker:
    file: str
    line: int
    rule: str
    reason: str


@dataclass(frozen=True)
class Row:
    file: str
    rule: str
    justification: str
    date: str


def find_markers(root: Path) -> list[Marker]:
    """Every inline ``codeql[...]`` justification comment in the scanned source trees."""
    markers: list[Marker] = []
    for top in SCAN_ROOTS:
        base = root / top
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            rel = path.relative_to(root)
            if path.suffix not in SCAN_SUFFIXES or SKIP_DIRS.intersection(rel.parts):
                continue
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for no, line in enumerate(text.splitlines(), start=1):
                for m in MARKER.finditer(line):
                    markers.append(
                        Marker(rel.as_posix(), no, m.group("rule"), m.group("reason").strip())
                    )
    return markers


def _cell(raw: str) -> str:
    cell = raw.strip()
    if len(cell) > 1 and cell[0] == "`" and cell[-1] == "`":
        cell = cell[1:-1].strip()
    return cell


def parse_table(doc_text: str) -> list[Row]:
    """Rows of the first markdown table after the "Accepted findings" heading."""
    rows: list[Row] = []
    in_section = False
    in_table = False
    for line in doc_text.splitlines():
        if not in_section:
            in_section = bool(TABLE_HEADING.match(line))
            continue
        stripped = line.strip()
        if stripped.startswith("|"):
            in_table = True
            cells = [_cell(c) for c in stripped.strip("|").split("|")]
            if cells and cells[0].lower() == "file":
                continue
            if all(set(c) <= set("-: ") for c in cells):
                continue
            cells += [""] * (4 - len(cells))
            rows.append(Row(cells[0], cells[1], cells[2], cells[3]))
        elif in_table or stripped.startswith("#"):
            break
    return rows


def check_consistency(markers: Iterable[Marker], rows: Iterable[Row]) -> list[str]:
    """Problems that break the "inline marker AND table row" rule."""
    errors: list[str] = []
    markers = list(markers)
    rows = list(rows)
    row_keys = {(r.file, r.rule) for r in rows}
    marker_keys = {(m.file, m.rule) for m in markers}
    for m in markers:
        if not m.reason:
            errors.append(f"{m.file}:{m.line}: inline codeql[{m.rule}] marker has no reason")
        if (m.file, m.rule) not in row_keys:
            errors.append(
                f"{m.file}:{m.line}: inline codeql[{m.rule}] marker has no row in the "
                f"Accepted findings table of {SECURITY_DOC.as_posix()}"
            )
    seen: set[tuple[str, str]] = set()
    for r in rows:
        key = (r.file, r.rule)
        if key in seen:
            errors.append(f"Accepted findings table: duplicate row for {r.file} {r.rule}")
        seen.add(key)
        if not r.file or not r.rule or not r.justification:
            errors.append(f"Accepted findings table: incomplete row {r}")
        if not DATE.match(r.date):
            errors.append(f"Accepted findings table: row {r.file} {r.rule} needs a YYYY-MM-DD date")
        if key not in marker_keys:
            errors.append(
                f"Accepted findings table: row {r.file} {r.rule} has no inline "
                f"codeql[{r.rule}] marker in that file"
            )
    return errors


def check_sarif(sarif_dir: Path, markers: Iterable[Marker], rows: Iterable[Row]) -> list[str]:
    """Error/warning results that are not accepted by both an inline marker and a table row."""
    marker_at = {(m.file, m.line, m.rule) for m in markers}
    row_keys = {(r.file, r.rule) for r in rows}
    errors: list[str] = []
    for f in sorted(sarif_dir.glob("*.sarif")):
        for run in json.loads(f.read_text(encoding="utf-8"))["runs"]:
            for res in run.get("results", []):
                if res.get("level", "warning") not in ("error", "warning"):
                    continue
                loc = res["locations"][0]["physicalLocation"]
                uri = loc["artifactLocation"]["uri"]
                line = int(loc.get("region", {}).get("startLine", 1))
                rule = res["ruleId"]
                where = f"{uri}:{line} {rule}: {res['message']['text']}"
                if (uri, line, rule) in marker_at and (uri, rule) in row_keys:
                    print(f"accepted (inline marker + table row): {where}")
                    continue
                print(f"::error file={uri},line={line}::{rule}: {res['message']['text']}")
                errors.append(f"FINDING {where}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--sarif-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    root: Path = args.root

    markers = find_markers(root)
    rows = parse_table((root / SECURITY_DOC).read_text(encoding="utf-8"))
    errors = check_consistency(markers, rows)
    if args.sarif_dir is not None:
        errors += check_sarif(args.sarif_dir, markers, rows)

    for r in rows:
        print(f"accepted finding: {r.file} {r.rule} ({r.date}) - {r.justification}")
    for e in errors:
        print(e)
    print(f"CodeQL gate: {len(rows)} accepted finding(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
