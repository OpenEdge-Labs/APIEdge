#!/usr/bin/env python3
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Build and verify the APIEdge release artifacts (used by .github/workflows/release.yml).

Uses only the Python standard library plus pip/setuptools from requirements/build.lock.
Run it with the Python of an environment that has build.lock installed (for example the
``.venv`` created by ``python scripts/install.py --local``):

  python scripts/build-release.py build --out dist/release [--tag v0.1.0] [--helm] [--docs-site DIR]
  python scripts/build-release.py verify dist/release
  python scripts/build-release.py smoke <apiedge executable> --data-dir DIR [--port 18080]

``build`` writes into ``--out``:

* ``apiedge-<version>-py3-none-any.whl``      the wheel, with the prebuilt console inside
* ``apiedge-<version>-installer-<os>.zip``    one-click installer bundle for windows, macos, linux
* ``apiedge-<version>.cdx.json``              CycloneDX 1.5 SBOM (Python runtime + console npm)
* ``apiedge-<chart version>.tgz``             Helm chart (with ``--helm``; needs the helm CLI)
* ``apiedge-<version>-docs.zip``              documentation site (with ``--docs-site``, the output
                                             of ``mkdocs build --strict``)
* ``SHA256SUMS``                              sha256 of every file above (``sha256sum -c`` format)

Third-party packages are never bundled: the installer bundles download them from PyPI with
``--require-hashes`` exactly like a git checkout does. Signing (``SHA256SUMS.asc``) is done by
the workflow only when a signing key is configured.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 - runs git/pip/helm with argument lists, never a shell
import sys
import uuid
import zipfile
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
NAME = "apiedge"
SUPPLIER = "OpenEdge Labs"
HOMEPAGE = "https://github.com/OpenEdge-Labs/APIEdge"
CHART_DIR = ROOT / "packaging" / "helm" / "apiedge"

# Files every installer bundle contains (prefix match on git-tracked paths).
BUNDLE_COMMON = (
    "src/",
    "requirements/",
    "docs/",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_LICENSES.md",
    "CHANGELOG.md",
    ".env.example",
    "scripts/install.py",
)
# OS-specific launchers: double-click entry point plus its bootstrap.
BUNDLE_OS: dict[str, tuple[str, ...]] = {
    "windows": ("install.bat", "scripts/install.ps1"),
    "macos": ("install.command", "install.sh", "scripts/install.sh"),
    "linux": ("install.sh", "scripts/install.sh"),
}
EXECUTABLE_SUFFIXES = (".sh", ".command")
# Wheel members that prove the console and migrations were packaged.
WHEEL_REQUIRED = (
    "apiedge/__init__.py",
    "apiedge/cli.py",
    "apiedge/py.typed",
    "apiedge/static/index.html",
    "apiedge/db/migrations/env.py",
)

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)")


class ReleaseError(RuntimeError):
    """A release build or verification step failed."""


# ---------------------------------------------------------------- versions
def project_version(pyproject: Path = ROOT / "pyproject.toml") -> str:
    """Read ``[project] version`` without tomllib (Python 3.10 has none)."""
    in_project = False
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
        elif in_project:
            m = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    raise ReleaseError("no [project] version in pyproject.toml")


def check_tag(version: str, tag: str | None) -> None:
    """A release tag must be exactly ``v<version>`` so artifacts and tags never disagree."""
    if tag and tag != f"v{version}":
        raise ReleaseError(f"tag {tag!r} does not match the project version {version!r}")


def chart_version(version: str) -> str:
    """Map a PEP 440 version to the SemVer 2 version Helm requires (0.1.0.dev0 -> 0.1.0-dev.0)."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.?(a|b|rc|dev)\.?(\d+))?", version)
    if not m:
        raise ReleaseError(f"cannot map version {version!r} to SemVer")
    core = ".".join(m.group(1, 2, 3))
    if m.group(4):
        pre = {"a": "alpha", "b": "beta"}.get(m.group(4), m.group(4))
        return f"{core}-{pre}.{m.group(5)}"
    return core


# ---------------------------------------------------------------- bundles
def tracked_files(root: Path = ROOT) -> list[str]:
    """Files under version control: build output, venvs and local data can never leak in."""
    git = shutil.which("git")
    if git is None:
        raise ReleaseError("git is required to list the files of a release")
    out = subprocess.run(  # nosec B603
        [git, "-C", str(root), "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def bundle_members(files: Iterable[str], os_name: str) -> list[str]:
    """Pick the git-tracked files that belong in the installer bundle for ``os_name``."""
    if os_name not in BUNDLE_OS:
        raise ReleaseError(f"unknown OS {os_name!r}")
    wanted = BUNDLE_COMMON + BUNDLE_OS[os_name]
    picked = [
        f for f in files if any(f == w or (w.endswith("/") and f.startswith(w)) for w in wanted)
    ]
    for launcher in BUNDLE_OS[os_name]:
        if launcher not in picked:
            raise ReleaseError(f"{launcher} is missing from the source tree")
    return picked


def _zip_time() -> tuple[int, int, int, int, int, int]:
    """Fixed member timestamps (SOURCE_DATE_EPOCH when set) for reproducible archives."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        dt = datetime.fromtimestamp(max(int(epoch), 315532800), tz=timezone.utc)
        return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    return (1980, 1, 1, 0, 0, 0)


def write_bundle(root: Path, members: list[str], dest: Path, prefix: str) -> None:
    """Zip ``members`` under ``prefix/``; shell launchers keep their executable bit."""
    stamp = _zip_time()
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in members:
            info = zipfile.ZipInfo(f"{prefix}/{rel}", date_time=stamp)
            mode = 0o755 if rel.endswith(EXECUTABLE_SUFFIXES) else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.create_system = 3  # Unix, so unzip / Archive Utility honour the mode bits
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, (root / rel).read_bytes())


def write_docs_zip(site: Path, dest: Path, prefix: str) -> int:
    """Zip a built documentation site under ``prefix/``; returns the number of files."""
    if not (site / "index.html").is_file():
        raise ReleaseError(f"{site} is not a built documentation site (no index.html)")
    members = sorted(p.relative_to(site).as_posix() for p in site.rglob("*") if p.is_file())
    write_bundle(site, members, dest, prefix)
    return len(members)


# ---------------------------------------------------------------- wheel
def build_wheel(out: Path) -> Path:
    """Build the wheel offline with the hash-locked setuptools of build.lock (no isolation)."""
    # A stale setuptools build/ directory could put deleted files into the wheel.
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    before = set(out.glob("*.whl"))
    subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(out),
            str(ROOT),
        ],
        check=True,
    )
    created = sorted(set(out.glob("*.whl")) - before)
    if len(created) != 1:
        raise ReleaseError(f"expected one new wheel, found {[p.name for p in created]}")
    return created[0]


def verify_wheel(wheel: Path, version: str) -> list[str]:
    """Return problems: missing console/migrations, foreign top-level packages, no license."""
    problems: list[str] = []
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    info_dir = f"{NAME}-{version}.dist-info/"
    for required in WHEEL_REQUIRED:
        if required not in names:
            problems.append(f"missing {required}")
    if not any(
        n.startswith("apiedge/db/migrations/versions/") and n.endswith(".py") for n in names
    ):
        problems.append("missing database migrations")
    if not any(n.startswith("apiedge/static/assets/") for n in names):
        problems.append("missing console assets")
    for lic in ("LICENSE", "NOTICE"):
        if not any(n.startswith(info_dir) and n.endswith(f"/{lic}") for n in names):
            problems.append(f"missing {lic} in {info_dir}")
    foreign = sorted({n.split("/")[0] for n in names} - {NAME, info_dir.rstrip("/")})
    if foreign:
        problems.append(f"unexpected top-level entries (third-party code?): {foreign}")
    if any("__pycache__" in n or n.endswith(".pyc") for n in names):
        problems.append("compiled bytecode in the wheel")
    return problems


# ---------------------------------------------------------------- SBOM
def lock_pins(lock: Path) -> list[tuple[str, str]]:
    """(name, version) of every pin in a hash lock, environment markers ignored, de-duplicated."""
    pins: dict[str, str] = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        m = _PIN.match(line)
        if m:
            pins[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    return sorted(pins.items())


def _license_lookup() -> Any:
    """Load scripts/check-licenses.py so a package's license is defined in one place only."""
    spec = importlib.util.spec_from_file_location(
        "apiedge_check_licenses", SCRIPTS / "check-licenses.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - file is part of the repo
        raise ReleaseError("cannot load scripts/check-licenses.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def python_licenses(names: Iterable[str]) -> dict[str, str]:
    """License strings of installed distributions (the build venv has runtime.lock installed)."""
    from importlib.metadata import PackageNotFoundError, distribution

    checker = _license_lookup()
    found: dict[str, str] = {}
    for name in names:
        try:
            lic = str(checker.license_of(distribution(name)))
        except PackageNotFoundError:
            continue
        if lic != "UNKNOWN":
            found[name] = lic
    return found


def npm_runtime_packages(lock: Path, node_modules: Path | None) -> list[dict[str, Any]]:
    """Production (non-dev) npm packages bundled into the built console."""
    if not lock.exists():
        return []
    data = json.loads(lock.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for path, meta in sorted(data.get("packages", {}).items()):
        if not path or meta.get("dev") or meta.get("devOptional"):
            continue
        name = path.split("node_modules/")[-1]
        entry: dict[str, Any] = {"name": name, "version": meta.get("version", "")}
        integrity = str(meta.get("integrity", ""))
        if integrity.startswith("sha512-"):
            entry["sha512"] = base64.b64decode(integrity[7:]).hex()
        lic = meta.get("license")
        if not lic and node_modules is not None:
            pkg_json = node_modules / name / "package.json"
            if pkg_json.exists():
                lic = json.loads(pkg_json.read_text(encoding="utf-8")).get("license")
        if isinstance(lic, str) and lic:
            entry["license"] = lic
        out.append(entry)
    return out


def _license_entry(lic: str) -> list[dict[str, Any]]:
    # A simple SPDX id goes in license.id; anything else (expressions, classifier text) as a name.
    if re.fullmatch(r"[A-Za-z0-9.+-]+", lic):
        return [{"license": {"id": lic}}]
    if re.fullmatch(r"[A-Za-z0-9.+() -]+", lic) and (" OR " in lic or " AND " in lic):
        return [{"expression": lic}]
    return [{"license": {"name": lic}}]


def build_sbom(
    version: str,
    python_pins: list[tuple[str, str]],
    licenses: dict[str, str],
    npm: list[dict[str, Any]],
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """A CycloneDX 1.5 JSON SBOM of what an installed APIEdge release runs."""
    ts = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
    components: list[dict[str, Any]] = []
    for name, ver in python_pins:
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{ver}",
            "name": name,
            "version": ver,
            "purl": f"pkg:pypi/{name}@{ver}",
            "scope": "required",
        }
        if name in licenses:
            comp["licenses"] = _license_entry(licenses[name])
        components.append(comp)
    for pkg in npm:
        purl = f"pkg:npm/{pkg['name'].replace('@', '%40')}@{pkg['version']}"
        comp = {
            "type": "library",
            "bom-ref": purl,
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": purl,
            "scope": "required",
            "properties": [{"name": "apiedge:bundled-in", "value": "web console (static files)"}],
        }
        if "sha512" in pkg:
            comp["hashes"] = [{"alg": "SHA-512", "content": pkg["sha512"]}]
        if "license" in pkg:
            comp["licenses"] = _license_entry(pkg["license"])
        components.append(comp)
    self_ref = f"pkg:pypi/{NAME}@{version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {"type": "application", "name": "apiedge-build-release", "version": version}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": self_ref,
                "name": NAME,
                "version": version,
                "purl": self_ref,
                "supplier": {"name": SUPPLIER, "url": [HOMEPAGE]},
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": components,
        "dependencies": [{"ref": self_ref, "dependsOn": [c["bom-ref"] for c in components]}],
    }


def validate_sbom(sbom: dict[str, Any]) -> list[str]:
    """Structural checks for the fields consumers (Dependency-Track, grype, ...) rely on."""
    problems = []
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        problems.append("not a CycloneDX 1.5 document")
    if not re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", str(sbom.get("serialNumber", ""))):
        problems.append("invalid serialNumber")
    comps = sbom.get("components", [])
    if not comps:
        problems.append("no components")
    refs = [c.get("bom-ref") for c in comps]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-ref")
    for c in comps:
        if (
            not c.get("name")
            or not c.get("version")
            or not str(c.get("purl", "")).startswith("pkg:")
        ):
            problems.append(f"incomplete component {c.get('name')!r}")
    return problems


# ---------------------------------------------------------------- checksums
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(directory: Path) -> Path:
    """``SHA256SUMS`` in GNU coreutils format, over every regular file except itself/signatures."""
    files = sorted(
        p
        for p in directory.iterdir()
        if p.is_file() and p.name != "SHA256SUMS" and not p.name.endswith((".asc", ".sig"))
    )
    if not files:
        raise ReleaseError(f"nothing to checksum in {directory}")
    sums = directory / "SHA256SUMS"
    lines = [f"{sha256_file(p)}  {p.name}" for p in files]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return sums


def verify_checksums(directory: Path) -> list[str]:
    """Problems with ``SHA256SUMS``: missing, mismatched or unlisted files."""
    sums = directory / "SHA256SUMS"
    if not sums.exists():
        return ["SHA256SUMS is missing"]
    problems, listed = [], set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", line)
        if not m:
            problems.append(f"malformed line: {line!r}")
            continue
        name = m.group(2)
        listed.add(name)
        path = directory / name
        if not path.is_file():
            problems.append(f"{name}: missing")
        elif sha256_file(path) != m.group(1):
            problems.append(f"{name}: checksum mismatch")
    for p in directory.iterdir():
        signature = p.name.endswith((".asc", ".sig"))
        if p.is_file() and p.name not in listed and p.name != "SHA256SUMS" and not signature:
            problems.append(f"{p.name}: not listed in SHA256SUMS")
    return problems


# ---------------------------------------------------------------- commands
def cmd_build(args: argparse.Namespace) -> int:
    version = project_version()
    tag = args.tag
    if tag is None and os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ.get("GITHUB_REF_NAME")
    check_tag(version, tag)
    out: Path = args.out.resolve()
    if args.docs_site:
        site = args.docs_site.resolve()
        if site.is_relative_to(ROOT / "build"):
            # build_wheel() deletes ROOT/build (stale setuptools output) before building.
            raise ReleaseError(f"--docs-site must be outside {ROOT / 'build'}: it is cleaned")
        if not (site / "index.html").is_file():
            raise ReleaseError(f"{site} is not a built documentation site (no index.html)")
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    print(f"APIEdge {version}: building release artifacts in {out}", flush=True)

    wheel = build_wheel(out)
    problems = verify_wheel(wheel, version)
    if problems:
        raise ReleaseError(f"{wheel.name}: " + "; ".join(problems))
    print(f"  wheel   {wheel.name}")

    files = tracked_files()
    for os_name in BUNDLE_OS:
        dest = out / f"{NAME}-{version}-installer-{os_name}.zip"
        write_bundle(ROOT, bundle_members(files, os_name), dest, f"{NAME}-{version}")
        print(f"  bundle  {dest.name}")

    pins = lock_pins(ROOT / "requirements" / "runtime.lock")
    npm_dir = ROOT / "console" / "node_modules"
    sbom = build_sbom(
        version,
        pins,
        python_licenses(name for name, _ in pins),
        npm_runtime_packages(
            ROOT / "console" / "package-lock.json", npm_dir if npm_dir.is_dir() else None
        ),
    )
    problems = validate_sbom(sbom)
    if problems:
        raise ReleaseError("SBOM: " + "; ".join(problems))
    sbom_path = out / f"{NAME}-{version}.cdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"  sbom    {sbom_path.name} ({len(sbom['components'])} components)")

    if args.helm:
        helm = shutil.which("helm")
        if helm is None:
            raise ReleaseError("--helm needs the helm CLI on PATH")
        cv = chart_version(version)
        subprocess.run(  # nosec B603
            [helm, "lint", str(CHART_DIR), "--strict"], check=True
        )
        subprocess.run(  # nosec B603
            [
                helm,
                "package",
                str(CHART_DIR),
                "--destination",
                str(out),
                "--version",
                cv,
                "--app-version",
                version,
            ],
            check=True,
        )
        print(f"  chart   {NAME}-{cv}.tgz")

    if args.docs_site:
        dest = out / f"{NAME}-{version}-docs.zip"
        count = write_docs_zip(args.docs_site.resolve(), dest, f"{NAME}-{version}-docs")
        print(f"  docs    {dest.name} ({count} files)")

    sums = write_checksums(out)
    print(f"  sums    {sums.name}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    problems = verify_checksums(args.directory)
    for wheel in args.directory.glob("*.whl"):
        m = re.match(rf"{NAME}-([^-]+)-", wheel.name)
        problems += [f"{wheel.name}: {p}" for p in verify_wheel(wheel, m.group(1) if m else "")]
    for p in problems:
        print(f"ERROR: {p}")
    if not problems:
        print(f"{args.directory}: all checksums and the wheel contents are valid")
    return 1 if problems else 0


def cmd_smoke(args: argparse.Namespace) -> int:
    """Start an installed ``apiedge`` and check /healthz and the console (reuses install.py)."""
    sys.path.insert(0, str(SCRIPTS))
    import install

    exe: Path = args.exe
    data_dir: Path = args.data_dir.resolve()
    env = dict(os.environ, APIEDGE_DATA_DIR=str(data_dir))
    run_args = ["--data-dir", str(data_dir)]
    subprocess.run([str(exe), "init", *run_args], env=env, check=True)  # nosec B603
    gateway_env = dict(env, APIEDGE_GATEWAY_PORT=str(args.port + 1))
    install.smoke_test(exe, [*run_args, "--port", str(args.port)], args.port, gateway_env)
    print("Smoke test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build all release artifacts")
    b.add_argument("--out", type=Path, default=ROOT / "dist" / "release")
    b.add_argument("--tag", help="release tag to check against the version (default: GITHUB_REF)")
    b.add_argument("--helm", action="store_true", help="also lint and package the Helm chart")
    b.add_argument(
        "--docs-site", type=Path, help="also zip this built documentation site (mkdocs output)"
    )
    b.set_defaults(func=cmd_build)
    v = sub.add_parser("verify", help="check SHA256SUMS and the wheel in a release directory")
    v.add_argument("directory", type=Path)
    v.set_defaults(func=cmd_verify)
    s = sub.add_parser("smoke", help="init, start and health-check an installed apiedge")
    s.add_argument("exe", type=Path, help="path of the apiedge executable")
    s.add_argument("--data-dir", type=Path, required=True)
    s.add_argument("--port", type=int, default=18080)
    s.set_defaults(func=cmd_smoke)
    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except (ReleaseError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
