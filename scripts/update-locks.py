#!/usr/bin/env python3
# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Maintainer tool: regenerate the hash-locked requirement files.

Reads ``requirements/{runtime,dev,build}.in`` (exact top-level pins) and writes
``requirements/*.lock`` that install on every supported target
(Windows x86_64, Linux x86_64/aarch64, macOS x86_64/arm64 x CPython 3.10-3.12):

1. Resolve the full set with pip's resolver (``pip install --dry-run --report``).
2. Walk the dependency graph once **per target environment**, evaluating each
   ``Requires-Dist`` marker (python_version, sys_platform, extras, ...) for that
   target, to find exactly which packages each target needs.
3. Emit a PEP 508 environment marker on every package that is not needed on
   all targets (e.g. ``tomli ; python_version < "3.11"``).
4. List the sha256 of every file PyPI publishes for each pinned version.
5. Verify: each pin's Requires-Python covers the Pythons that need it, a wheel
   exists for every target that needs it, and ``pip install --dry-run
   --require-hashes`` succeeds for every target with the markers applied.

Needs internet access (PyPI) and the ``packaging`` library: run it with the
developer venv, e.g. ``.venv/bin/python scripts/update-locks.py``.

Usage:  python scripts/update-locks.py [--check] [--skip-verify]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404 - runs pip with fixed arguments
import sys
import tempfile
import urllib.request
import venv
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements"
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"

PYTHONS = ("3.10", "3.11", "3.12")
FULL_VERSION = {"3.10": "3.10.12", "3.11": "3.11.9", "3.12": "3.12.7"}


@dataclass(frozen=True)
class Platform:
    label: str
    sys_platform: str
    platform_system: str
    machine: str
    os_name: str
    wheel_re: str  # matched against a wheel's platform tag
    pip_platforms: tuple[str, ...]  # --platform values for verification


def _manylinux(arch: str) -> tuple[str, ...]:
    tags = [f"manylinux_2_{m}_{arch}" for m in range(28, 16, -1)]
    tags += [f"manylinux2014_{arch}"]
    if arch == "x86_64":
        tags += [f"manylinux2010_{arch}", f"manylinux1_{arch}"]
    return tuple(tags)


PLATFORMS = (
    Platform("win_amd64", "win32", "Windows", "AMD64", "nt", r"win_amd64", ("win_amd64",)),
    Platform(
        "linux_x86_64",
        "linux",
        "Linux",
        "x86_64",
        "posix",
        r"manylinux.*x86_64",
        _manylinux("x86_64"),
    ),
    Platform(
        "linux_aarch64",
        "linux",
        "Linux",
        "aarch64",
        "posix",
        r"manylinux.*aarch64",
        _manylinux("aarch64"),
    ),
    Platform(
        "macos_x86_64",
        "darwin",
        "Darwin",
        "x86_64",
        "posix",
        r"macosx.*(x86_64|universal2|intel)",
        ("macosx_11_0_x86_64", "macosx_10_12_x86_64", "macosx_10_9_x86_64"),
    ),
    Platform(
        "macos_arm64",
        "darwin",
        "Darwin",
        "arm64",
        "posix",
        r"macosx.*(arm64|universal2)",
        ("macosx_11_0_arm64",),
    ),
)
Target = tuple[Platform, str]
TARGETS: tuple[Target, ...] = tuple((p, py) for p in PLATFORMS for py in PYTHONS)


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def marker_env(target: Target, extra: str = "") -> dict[str, str]:
    plat, py = target
    return {
        "python_version": py,
        "python_full_version": FULL_VERSION[py],
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
        "implementation_version": FULL_VERSION[py],
        "sys_platform": plat.sys_platform,
        "platform_system": plat.platform_system,
        "platform_machine": plat.machine,
        "os_name": plat.os_name,
        "platform_release": "",
        "platform_version": "",
        "extra": extra,
    }


# ---------------------------------------------------------------- resolution
@dataclass
class Dist:
    name: str
    version: str
    requires: list[Requirement]


def resolve(python: Path, req_files: list[Path], workdir: Path) -> dict[str, Dist]:
    report = workdir / f"report-{req_files[-1].stem}.json"
    cmd = [
        str(python),
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--quiet",
        "--report",
        str(report),
    ]
    for f in req_files:
        cmd += ["-r", str(f)]
    subprocess.run(cmd, check=True)  # nosec B603
    data = json.loads(report.read_text(encoding="utf-8"))
    out = {}
    for item in data["install"]:
        md = item["metadata"]
        name = canonical(md["name"])
        out[name] = Dist(name, md["version"], [Requirement(r) for r in md.get("requires_dist", [])])
    return out


def roots(req_files: Iterable[Path]) -> list[Requirement]:
    reqs = []
    for f in req_files:
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                reqs.append(Requirement(line))
    return reqs


def needed_for(target: Target, root_reqs: list[Requirement], dists: dict[str, Dist]) -> set[str]:
    """Packages needed on ``target``: graph walk with markers evaluated for that target."""
    done: dict[str, set[str]] = {}  # package -> extras already expanded ("" = base deps)
    queue: list[tuple[str, frozenset[str]]] = []

    def push(req: Requirement, extra: str) -> None:
        if req.marker is not None and not req.marker.evaluate(marker_env(target, extra)):
            return
        name = canonical(req.name)
        if name not in dists:
            raise SystemExit(
                f"error: {name} is required on {target[0].label}/py{target[1]} but was not "
                "resolved on this machine; add it to the .in file explicitly"
            )
        queue.append((name, frozenset(req.extras)))

    for r in root_reqs:
        push(r, "")
    while queue:
        name, extras = queue.pop()
        todo = ({""} | set(extras)) - done.setdefault(name, set())
        done[name] |= todo
        for extra in todo:
            for req in dists[name].requires:
                push(req, extra)
    return set(done)


def render_marker(targets: set[Target]) -> str | None:
    """Smallest readable PEP 508 marker selecting exactly ``targets``."""
    if targets == set(TARGETS):
        return None
    by_plat: dict[str, set[str]] = {}
    for plat, py in targets:
        by_plat.setdefault(plat.label, set()).add(py)
    groups: dict[frozenset[str], list[Platform]] = {}
    for plat in PLATFORMS:
        if plat.label in by_plat:
            groups.setdefault(frozenset(by_plat[plat.label]), []).append(plat)
    clauses = []
    for pys, plats in groups.items():
        parts = []
        plat_clause = _platform_clause(plats)
        if plat_clause:
            parts.append(plat_clause)
        py_clause = _python_clause(pys)
        if py_clause:
            parts.append(py_clause)
        clauses.append(" and ".join(f"({p})" if " or " in p else p for p in parts))
    marker = " or ".join(f"({c})" if " and " in c and len(clauses) > 1 else c for c in clauses)
    Marker(marker)  # validate syntax
    return marker


def _platform_clause(plats: list[Platform]) -> str | None:
    if len(plats) == len(PLATFORMS):
        return None
    chosen = {p.label for p in plats}
    parts = []
    for sysplat in dict.fromkeys(p.sys_platform for p in PLATFORMS):
        family = [p for p in PLATFORMS if p.sys_platform == sysplat]
        picked = [p for p in family if p.label in chosen]
        if not picked:
            continue
        if len(picked) == len(family):
            parts.append(f'sys_platform == "{sysplat}"')
        else:
            parts += [
                f'(sys_platform == "{sysplat}" and platform_machine == "{p.machine}")'
                for p in picked
            ]
    return " or ".join(parts)


def _python_clause(pys: frozenset[str]) -> str | None:
    if len(pys) == len(PYTHONS):
        return None
    ordered = [p for p in PYTHONS if p in pys]
    idx = [PYTHONS.index(p) for p in ordered]
    if idx == list(range(len(idx))):  # a prefix: 3.10[, 3.11]
        nxt = PYTHONS[len(idx)]
        return f'python_version < "{nxt}"'
    if idx == list(range(len(PYTHONS) - len(idx), len(PYTHONS))):  # a suffix
        return f'python_version >= "{ordered[0]}"'
    return " or ".join(f'python_version == "{p}"' for p in ordered)


# ---------------------------------------------------------------- PyPI data
@cache
def pypi(name: str, version: str) -> dict[str, Any]:
    url = PYPI_JSON.format(name=name, version=version)
    with urllib.request.urlopen(url, timeout=60) as resp:  # nosec B310 - fixed https URL
        data: dict[str, Any] = json.load(resp)
    return data


def has_wheel(files: list[dict[str, Any]], plat: Platform, py: str) -> bool:
    cp = "cp" + py.replace(".", "")
    for f in files:
        fn = str(f["filename"])
        if not fn.endswith(".whl"):
            continue
        pytag, abitag, plattag = fn[:-4].split("-")[-3:]
        pys, abis = pytag.split("."), abitag.split(".")
        if plattag == "any" and ("py3" in pys or cp in pys or "py" + cp[2:] in pys):
            return True
        if not re.search(plat.wheel_re, plattag):
            continue
        if cp in pys and (cp in abis or "none" in abis):
            return True
        if "abi3" in abis and any(p.startswith("cp3") and int(p[3:]) <= int(cp[3:]) for p in pys):
            return True
        if "py3" in pys and "none" in abis:
            return True
    return False


def check_pin(name: str, version: str, targets: set[Target]) -> list[str]:
    data = pypi(name, version)
    problems = []
    rp = data["info"].get("requires_python")
    if rp:
        spec = SpecifierSet(rp)
        for py in sorted({py for _, py in targets}):
            if Version(FULL_VERSION[py]) not in spec:
                problems.append(f"{name}=={version} requires Python {rp}, needed on {py}")
    for plat, py in sorted(targets, key=lambda t: (t[0].label, t[1])):
        if not has_wheel(data["urls"], plat, py):
            problems.append(f"{name}=={version}: no wheel for {plat.label} / py{py}")
    return problems


# ---------------------------------------------------------------- output
@dataclass
class Pin:
    name: str
    version: str
    marker: str | None
    hashes: list[str]

    def line(self) -> str:
        return f"{self.name}=={self.version}" + (f" ; {self.marker}" if self.marker else "")


def build_pins(
    names: set[str], dists: dict[str, Dist], need: dict[Target, set[str]]
) -> tuple[list[Pin], list[str]]:
    pins, problems = [], []
    for name in sorted(names):
        targets = {t for t in TARGETS if name in need[t]}
        version = dists[name].version
        problems += check_pin(name, version, targets)
        hashes = sorted({str(f["digests"]["sha256"]) for f in pypi(name, version)["urls"]})
        pins.append(Pin(name, version, render_marker(targets), hashes))
    return pins, problems


def render_lock(title: str, note: str, pins: list[Pin]) -> str:
    lines = [
        f"# {title}",
        "# GENERATED by scripts/update-locks.py - do not edit by hand.",
        f"# {note}",
        "# Targets: Windows x86_64, Linux x86_64/aarch64, macOS x86_64/arm64 x CPython 3.10-3.12.",
        "# Environment markers select per-target packages; every PyPI file hash is listed.",
        "",
    ]
    for pin in pins:
        lines.append(pin.line() + " \\")
        for i, h in enumerate(pin.hashes):
            lines.append(f"    --hash=sha256:{h}" + (" \\" if i < len(pin.hashes) - 1 else ""))
    return "\n".join(lines) + "\n"


def verify(python: Path, workdir: Path, pin_sets: list[list[Pin]]) -> list[str]:
    """pip --dry-run --require-hashes per target, markers pre-evaluated for that target
    (pip itself would evaluate markers against the host interpreter)."""
    problems = []
    for target in TARGETS:
        plat, py = target
        env = marker_env(target)
        req = workdir / f"verify-{plat.label}-{py}.txt"
        lines = []
        for pins in pin_sets:
            for pin in pins:
                if pin.marker is None or Marker(pin.marker).evaluate(env):
                    lines.append(
                        f"{pin.name}=={pin.version} "
                        + " ".join(f"--hash=sha256:{h}" for h in pin.hashes)
                    )
        req.write_text("\n".join(lines) + "\n", encoding="utf-8")
        cp = "cp" + py.replace(".", "")
        cmd = [
            str(python),
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--quiet",
            "--ignore-installed",
            "--no-deps",
            "--require-hashes",
            "--only-binary=:all:",
            "--implementation",
            "cp",
            "--python-version",
            py,
            "--abi",
            cp,
            "--abi",
            "abi3",
            "--abi",
            "none",
            "--target",
            str(workdir / "t"),
            "-r",
            str(req),
        ]
        for p in plat.pip_platforms:
            cmd += ["--platform", p]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
        status = "ok" if result.returncode == 0 else "FAILED"
        print(f"  verify {plat.label:14} py{py}: {len(lines)} packages {status}")
        if result.returncode != 0:
            problems.append(f"{plat.label}/py{py}: {result.stderr.strip()[-600:]}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--check",
        action="store_true",
        help="fail if the generated locks differ from the committed ones",
    )
    ap.add_argument(
        "--skip-verify", action="store_true", help="skip the per-target pip dry-run verification"
    )
    args = ap.parse_args()

    runtime_in, dev_in, build_in = REQ / "runtime.in", REQ / "dev.in", REQ / "build.in"
    with tempfile.TemporaryDirectory(prefix="apiedge-lock-") as tmp:
        work = Path(tmp)
        venv.EnvBuilder(with_pip=True).create(work / "venv")
        py = work / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(
            [
                str(py),
                "-m",
                "pip",
                "install",
                "--quiet",
                "-r",  # nosec B603
                str(build_in),
            ],
            check=True,
        )

        all_dists = resolve(py, [runtime_in, dev_in], work)
        build_dists = resolve(py, [build_in], work)
        runtime_need = {t: needed_for(t, roots([runtime_in]), all_dists) for t in TARGETS}
        all_need = {t: needed_for(t, roots([runtime_in, dev_in]), all_dists) for t in TARGETS}
        build_need = {t: needed_for(t, roots([build_in]), build_dists) for t in TARGETS}

        runtime_names = set().union(*runtime_need.values())
        # A runtime-locked package that dev tools need on *more* targets (e.g. tomli: runtime
        # only on 3.10, pip-audit everywhere) gets a complementary dev.lock entry whose marker
        # covers just the extra targets, so exactly one line applies on any target.
        dev_need = {t: all_need[t] - runtime_need[t] for t in TARGETS}
        dev_names = set().union(*dev_need.values())
        problems: list[str] = []
        runtime_pins, p1 = build_pins(runtime_names, all_dists, runtime_need)
        dev_pins, p2 = build_pins(dev_names, all_dists, dev_need)
        build_pins_, p3 = build_pins(set().union(*build_need.values()), build_dists, build_need)
        problems += p1 + p2 + p3

        if not args.skip_verify and not problems:
            print("verifying every target (pip --dry-run --require-hashes):")
            problems += verify(py, work, [runtime_pins])
            problems += verify(py, work, [runtime_pins, dev_pins])
            problems += verify(py, work, [build_pins_])

    for p in problems:
        print(f"ERROR: {p}")
    if problems:
        return 1

    outputs = {
        "runtime.lock": render_lock(
            "APIEdge runtime lock", "Input: requirements/runtime.in", runtime_pins
        ),
        "dev.lock": render_lock(
            "APIEdge development lock (install together with runtime.lock)",
            "Input: requirements/dev.in (resolved with runtime.in)",
            dev_pins,
        ),
        "build.lock": render_lock(
            "APIEdge installer/build tooling lock", "Input: requirements/build.in", build_pins_
        ),
    }
    changed = False
    for fname, text in outputs.items():
        target = REQ / fname
        old = target.read_text(encoding="utf-8") if target.exists() else ""
        if old != text:
            changed = True
            if not args.check:
                target.write_text(text, encoding="utf-8", newline="\n")
                print(f"wrote {target.relative_to(ROOT)}")
    if args.check and changed:
        print("error: locks are out of date; run scripts/update-locks.py")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
