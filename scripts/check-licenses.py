#!/usr/bin/env python3
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""License gate for third-party Python packages.

Inspects every distribution installed in the current environment (run it with
the APIEdge venv's Python after installing runtime.lock + dev.lock), fails on
GPL / AGPL / SSPL licenses, and can (re)generate ``THIRD_PARTY_LICENSES.md``.

Usage:
  python scripts/check-licenses.py                 # check only
  python scripts/check-licenses.py --write         # check and write THIRD_PARTY_LICENSES.md
  python scripts/check-licenses.py --runtime-only  # restrict to requirements/runtime.lock
  python scripts/check-licenses.py --docs-only [--write]
      # with the docs venv's Python: check requirements/docs.lock and (re)write its own section
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib.metadata import Distribution, distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD_PARTY_LICENSES.md"
SELF = "apiedge"

FORBIDDEN = re.compile(r"\b(A?GPL|SSPL|GNU General Public|Affero|Server Side Public)", re.I)
REVIEW = re.compile(r"\b(LGPL|GNU Lesser)", re.I)
DOCS_HEADING = "## Documentation site tooling"


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_names(lock: Path) -> set[str]:
    names = set()
    for line in lock.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==", line)
        if m:
            names.add(canonical(m.group(1)))
    return names


def _field(dist: Distribution, key: str) -> str:
    values = dist.metadata.get_all(key) or []
    return str(values[0]) if values else ""


def license_of(dist: Distribution) -> str:
    md = dist.metadata
    expr = _field(dist, "License-Expression")
    if expr:
        return str(expr)
    classifiers = [
        c.split("::")[-1].strip()
        for c in md.get_all("Classifier") or []
        if c.startswith("License ::") and c.split("::")[-1].strip() != "OSI Approved"
    ]
    if classifiers:
        return "; ".join(classifiers)
    lic = _field(dist, "License").strip()
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic
    return "UNKNOWN"


def source_url(dist: Distribution) -> str:
    md = dist.metadata
    if _field(dist, "Home-page"):
        return _field(dist, "Home-page")
    for url in md.get_all("Project-URL") or []:
        label, _, link = url.partition(",")
        if label.strip().lower() in ("source", "homepage", "repository", "source code"):
            return str(link).strip()
    return f"https://pypi.org/project/{_field(dist, 'Name')}/"


def _existing_docs_section() -> list[str]:
    """The documentation-tooling section of THIRD_PARTY_LICENSES.md, kept across rewrites."""
    if not OUTPUT.exists():
        return []
    text = OUTPUT.read_text(encoding="utf-8")
    if DOCS_HEADING not in text:
        return []
    return ["", *text[text.index(DOCS_HEADING) :].rstrip("\n").splitlines()]


def _write_docs_section(rows: dict[str, tuple[str, str, str, str]]) -> None:
    section = [
        DOCS_HEADING,
        "",
        "Builds the documentation site in CI and release builds (`requirements/docs.lock`, a",
        "separate environment); never installed with APIEdge.",
        "",
        "| Package | Version | License | Source |",
        "|---|---|---|---|",
    ]
    for _, (display, ver, lic, url) in sorted(rows.items()):
        section.append(f"| {display} | {ver} | {lic} | {url} |")
    text = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if DOCS_HEADING in text:
        text = text[: text.index(DOCS_HEADING)]
    text = text.rstrip("\n") + "\n\n" + "\n".join(section) + "\n"
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote the documentation tooling section of {OUTPUT.relative_to(ROOT)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="write THIRD_PARTY_LICENSES.md")
    ap.add_argument("--runtime-only", action="store_true")
    ap.add_argument("--docs-only", action="store_true", help="requirements/docs.lock (docs venv)")
    args = ap.parse_args()

    if args.docs_only:
        wanted = lock_names(ROOT / "requirements" / "docs.lock")
    else:
        wanted = lock_names(ROOT / "requirements" / "runtime.lock")
    if not args.runtime_only and not args.docs_only:
        wanted |= lock_names(ROOT / "requirements" / "dev.lock")
        wanted |= lock_names(ROOT / "requirements" / "build.lock")

    rows: dict[str, tuple[str, str, str, str]] = {}
    for dist in distributions():
        name = canonical(dist.metadata["Name"])
        if name == SELF or name not in wanted:
            continue
        rows[name] = (dist.metadata["Name"], dist.version, license_of(dist), source_url(dist))

    missing = sorted(wanted - set(rows))
    errors, warnings = [], []
    for name, (_, ver, lic, _) in sorted(rows.items()):
        if FORBIDDEN.search(lic) and not REVIEW.search(lic):
            errors.append(f"{name} {ver}: forbidden license '{lic}'")
        elif REVIEW.search(lic) or lic == "UNKNOWN":
            warnings.append(f"{name} {ver}: license '{lic}' needs manual review")
    for w in warnings:
        print(f"warning: {w}")
    if missing:
        print(f"note: not installed here, not checked: {', '.join(missing)}")
    npm_lines, npm_errors = _npm_section()
    errors += npm_errors
    for e in errors:
        print(f"ERROR: {e}")

    if args.write and args.docs_only:
        if missing:
            errors.append("install requirements/docs.lock before writing its section")
        else:
            _write_docs_section(rows)
    elif args.write:
        runtime = lock_names(ROOT / "requirements" / "runtime.lock")
        lines = [
            "# Third-party licenses",
            "",
            "Generated by `scripts/check-licenses.py --write`. APIEdge itself is Apache-2.0.",
            "Packages are downloaded from PyPI / npm at install time and are not committed.",
            "",
            "## Python packages",
            "",
            "| Package | Version | License | Used for | Source |",
            "|---|---|---|---|---|",
        ]
        for name, (display, ver, lic, url) in sorted(rows.items()):
            scope = "runtime" if name in runtime else "development / install tooling"
            lines.append(f"| {display} | {ver} | {lic} | {scope} | {url} |")
        lines += npm_lines
        lines += _existing_docs_section()
        OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")

    print(f"checked {len(rows)} packages: {len(errors)} forbidden, {len(warnings)} to review")
    return 1 if errors else 0


def _npm_section() -> tuple[list[str], list[str]]:
    """List the console's npm packages from console/package-lock.json (developer-only)."""
    import json

    lock = ROOT / "console" / "package-lock.json"
    if not lock.exists():
        return [], []
    data = json.loads(lock.read_text(encoding="utf-8"))
    out = [
        "",
        "## Console npm packages (development only; the built console is committed)",
        "",
        "| Package | Version | License |",
        "|---|---|---|",
    ]
    errors = []
    for path, meta in sorted(data.get("packages", {}).items()):
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        out.append(f"| {name} | {meta.get('version', '?')} | {meta.get('license', 'UNKNOWN')} |")
        lic = str(meta.get("license", ""))
        if FORBIDDEN.search(lic) and not REVIEW.search(lic):
            errors.append(f"npm {name}: forbidden license '{lic}'")
    return out, errors


if __name__ == "__main__":
    sys.exit(main())
