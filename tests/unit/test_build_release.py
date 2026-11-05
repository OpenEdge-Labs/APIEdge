# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the release tooling (scripts/build-release.py) and the packaging files."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "apiedge_build_release", ROOT / "scripts" / "build-release.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


br = _load()
needs_git = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout"
)


# ---------------------------------------------------------------- versions
def test_project_version_matches_pyproject() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{br.project_version()}"' in text


@pytest.mark.parametrize(
    ("pep440", "semver"),
    [
        ("0.1.0.dev0", "0.1.0-dev.0"),
        ("1.2.3", "1.2.3"),
        ("1.0.0rc1", "1.0.0-rc.1"),
        ("2.0.0a3", "2.0.0-alpha.3"),
        ("2.0.0b1", "2.0.0-beta.1"),
    ],
)
def test_chart_version_maps_pep440_to_semver(pep440: str, semver: str) -> None:
    assert br.chart_version(pep440) == semver


def test_chart_version_rejects_unknown_formats() -> None:
    with pytest.raises(br.ReleaseError):
        br.chart_version("1.0")


def test_helm_chart_versions_follow_the_project_version() -> None:
    chart = (ROOT / "packaging" / "helm" / "apiedge" / "Chart.yaml").read_text(encoding="utf-8")
    version = br.project_version()
    assert re.search(rf"^version: {re.escape(br.chart_version(version))}$", chart, re.M)
    assert re.search(rf'^appVersion: "{re.escape(version)}"$', chart, re.M)


def test_tag_must_match_version() -> None:
    br.check_tag("1.2.3", None)
    br.check_tag("1.2.3", "v1.2.3")
    with pytest.raises(br.ReleaseError):
        br.check_tag("1.2.3", "v1.2.4")
    with pytest.raises(br.ReleaseError):
        br.check_tag("1.2.3", "1.2.3")


# ---------------------------------------------------------------- bundles
SAMPLE_TREE = [
    ".github/workflows/ci.yml",
    ".vscode/settings.json",
    "LOCAL_NOTES.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "console/src/App.tsx",
    "docs/installation.md",
    "install.bat",
    "install.command",
    "install.sh",
    "packaging/docker/Dockerfile",
    "pyproject.toml",
    "requirements/runtime.lock",
    "scripts/build-release.py",
    "scripts/install.ps1",
    "scripts/install.py",
    "scripts/install.sh",
    "scripts/update-locks.py",
    "src/apiedge/__init__.py",
    "src/apiedge/static/index.html",
    "tests/unit/test_x.py",
]


@pytest.mark.parametrize(
    ("os_name", "present", "absent"),
    [
        ("windows", {"install.bat", "scripts/install.ps1"}, {"install.sh", "install.command"}),
        ("macos", {"install.command", "install.sh", "scripts/install.sh"}, {"install.bat"}),
        ("linux", {"install.sh", "scripts/install.sh"}, {"install.bat", "install.command"}),
    ],
)
def test_bundle_members_per_os(os_name: str, present: set[str], absent: set[str]) -> None:
    members = set(br.bundle_members(SAMPLE_TREE, os_name))
    common = {
        "LICENSE",
        "NOTICE",
        "pyproject.toml",
        "scripts/install.py",
        "src/apiedge/__init__.py",
    }
    assert present | common <= members
    assert "src/apiedge/static/index.html" in members  # the prebuilt console
    assert not members & absent
    # Never shipped: dev tooling, tests, console sources, CI, editor and local files.
    for path in members:
        assert not path.startswith((".vscode/", ".github/", "console/", "tests/", "packaging/"))
    assert "LOCAL_NOTES.md" not in members
    assert "scripts/update-locks.py" not in members
    assert "scripts/build-release.py" not in members


def test_bundle_members_rejects_unknown_os_and_missing_launcher() -> None:
    with pytest.raises(br.ReleaseError):
        br.bundle_members(SAMPLE_TREE, "solaris")
    with pytest.raises(br.ReleaseError, match=r"install\.bat"):
        br.bundle_members([p for p in SAMPLE_TREE if p != "install.bat"], "windows")


def test_write_bundle_keeps_executable_bits(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "scripts" / "install.py").write_text("print()\n", encoding="utf-8")
    dest = tmp_path / "bundle.zip"
    br.write_bundle(tmp_path, ["install.sh", "scripts/install.py"], dest, "apiedge-1.0.0")
    with zipfile.ZipFile(dest) as zf:
        modes = {i.filename: (i.external_attr >> 16) & 0o777 for i in zf.infolist()}
        stamps = {i.date_time for i in zf.infolist()}
    assert modes == {"apiedge-1.0.0/install.sh": 0o755, "apiedge-1.0.0/scripts/install.py": 0o644}
    assert stamps == {(1980, 1, 1, 0, 0, 0)}  # reproducible


@needs_git
def test_real_tree_bundles_contain_no_third_party_code() -> None:
    files = br.tracked_files()
    for os_name in br.BUNDLE_OS:
        for path in br.bundle_members(files, os_name):
            assert not path.endswith((".whl", ".tar.gz", ".tgz", ".zip"))
            assert "node_modules/" not in path
            assert "site-packages/" not in path


@needs_git
def test_shell_launchers_are_executable_in_git() -> None:
    out = subprocess.run(  # noqa: S603 - fixed arguments
        ["git", "-C", str(ROOT), "ls-files", "-s", "--", "*.sh", "*.command"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    modes = {line.split()[3]: line.split()[0] for line in out.splitlines()}
    assert "packaging/docker/entrypoint.sh" in modes
    assert set(modes.values()) == {"100755"}, modes


# ---------------------------------------------------------------- wheel
def _wheel(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, "x")
    return path


GOOD_WHEEL = [
    *br.WHEEL_REQUIRED,
    "apiedge/db/migrations/versions/0001_initial.py",
    "apiedge/static/assets/index-abc.js",
    "apiedge-1.0.0.dist-info/METADATA",
    "apiedge-1.0.0.dist-info/licenses/LICENSE",
    "apiedge-1.0.0.dist-info/licenses/NOTICE",
]


def test_verify_wheel_accepts_a_complete_wheel(tmp_path: Path) -> None:
    assert br.verify_wheel(_wheel(tmp_path / "a.whl", GOOD_WHEEL), "1.0.0") == []


def test_verify_wheel_flags_missing_console_and_foreign_packages(tmp_path: Path) -> None:
    names = [n for n in GOOD_WHEEL if "static" not in n] + ["requests/__init__.py"]
    problems = br.verify_wheel(_wheel(tmp_path / "b.whl", names), "1.0.0")
    joined = "; ".join(problems)
    assert "apiedge/static/index.html" in joined
    assert "console assets" in joined
    assert "requests" in joined


def test_verify_wheel_flags_missing_license_and_bytecode(tmp_path: Path) -> None:
    names = [n for n in GOOD_WHEEL if not n.endswith("NOTICE")]
    names.append("apiedge/__pycache__/cli.cpython-312.pyc")
    problems = br.verify_wheel(_wheel(tmp_path / "c.whl", names), "1.0.0")
    assert any("NOTICE" in p for p in problems)
    assert any("bytecode" in p for p in problems)


# ---------------------------------------------------------------- SBOM
def test_lock_pins_ignore_markers_and_duplicates(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    lock.write_text(
        "# comment\n"
        "Foo_Bar==1.0 \\\n    --hash=sha256:aa\n"
        'tomli==2.5.0 ; python_version < "3.11" \\\n    --hash=sha256:bb\n'
        'tomli==2.5.0 ; python_version < "3.11" and sys_platform == "win32"\n',
        encoding="utf-8",
    )
    assert br.lock_pins(lock) == [("foo-bar", "1.0"), ("tomli", "2.5.0")]


def test_runtime_lock_pins_are_found() -> None:
    names = dict(br.lock_pins(ROOT / "requirements" / "runtime.lock"))
    assert {"fastapi", "uvicorn", "sqlalchemy", "pydantic"} <= set(names)


def test_npm_runtime_packages_skip_dev_and_decode_integrity(tmp_path: Path) -> None:
    digest = hashlib.sha512(b"react").digest()
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "console"},
                    "node_modules/react": {
                        "version": "18.3.1",
                        "integrity": "sha512-" + base64.b64encode(digest).decode(),
                    },
                    "node_modules/@scope/lib": {"version": "1.0.0", "license": "MIT"},
                    "node_modules/vite": {"version": "6.0.0", "dev": True},
                }
            }
        ),
        encoding="utf-8",
    )
    nm = tmp_path / "node_modules" / "react"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"license": "MIT"}', encoding="utf-8")
    pkgs = br.npm_runtime_packages(lock, tmp_path / "node_modules")
    assert [p["name"] for p in pkgs] == ["@scope/lib", "react"]
    react = pkgs[1]
    assert react["sha512"] == digest.hex()
    assert react["license"] == "MIT"


def test_sbom_is_valid_cyclonedx() -> None:
    sbom = br.build_sbom(
        "1.0.0",
        [("fastapi", "0.162.0"), ("greenlet", "3.5.6"), ("certifi", "2026.10.23")],
        {
            "fastapi": "MIT",
            "greenlet": "MIT AND PSF-2.0",
            "certifi": "Mozilla Public License 2.0 (MPL 2.0)",
        },
        [{"name": "@scope/lib", "version": "1.0.0", "license": "MIT", "sha512": "ab"}],
        timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )
    assert br.validate_sbom(sbom) == []
    assert sbom["metadata"]["timestamp"] == "2026-01-02T03:04:05Z"
    assert sbom["metadata"]["component"]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    comps = {c["name"]: c for c in sbom["components"]}
    assert comps["fastapi"]["purl"] == "pkg:pypi/fastapi@0.162.0"
    assert comps["fastapi"]["licenses"] == [{"license": {"id": "MIT"}}]
    assert comps["greenlet"]["licenses"] == [{"expression": "MIT AND PSF-2.0"}]
    assert comps["certifi"]["licenses"][0]["license"]["name"].startswith("Mozilla")
    assert comps["@scope/lib"]["purl"] == "pkg:npm/%40scope/lib@1.0.0"
    assert comps["@scope/lib"]["hashes"] == [{"alg": "SHA-512", "content": "ab"}]
    assert sbom["dependencies"][0]["ref"] == "pkg:pypi/apiedge@1.0.0"
    assert len(sbom["dependencies"][0]["dependsOn"]) == 4
    json.dumps(sbom)  # serialisable


def test_validate_sbom_reports_problems() -> None:
    bad = {"bomFormat": "SPDX", "serialNumber": "x", "components": [{"name": "a", "bom-ref": "r"}]}
    problems = br.validate_sbom(bad)
    assert any("CycloneDX" in p for p in problems)
    assert any("serialNumber" in p for p in problems)
    assert any("incomplete" in p for p in problems)


# ---------------------------------------------------------------- checksums
def test_checksums_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    (tmp_path / "a.whl").write_bytes(b"wheel")
    (tmp_path / "b.zip").write_bytes(b"zip")
    sums = br.write_checksums(tmp_path)
    text = sums.read_text(encoding="utf-8")
    assert f"{hashlib.sha256(b'wheel').hexdigest()}  a.whl" in text
    assert br.verify_checksums(tmp_path) == []

    (tmp_path / "SHA256SUMS.asc").write_text("signature", encoding="utf-8")
    assert br.verify_checksums(tmp_path) == []  # signatures are not checksummed

    (tmp_path / "b.zip").write_bytes(b"tampered")
    (tmp_path / "extra.bin").write_bytes(b"?")
    problems = br.verify_checksums(tmp_path)
    assert "b.zip: checksum mismatch" in problems
    assert "extra.bin: not listed in SHA256SUMS" in problems

    (tmp_path / "a.whl").unlink()
    assert "a.whl: missing" in br.verify_checksums(tmp_path)


def test_checksums_reject_path_traversal_entries(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS").write_text("0" * 64 + "  ../etc/passwd\n", encoding="utf-8")
    assert any("malformed" in p for p in br.verify_checksums(tmp_path))


def test_write_checksums_needs_files(tmp_path: Path) -> None:
    with pytest.raises(br.ReleaseError):
        br.write_checksums(tmp_path)


# ---------------------------------------------------------------- container files
def test_dockerfile_is_pinned_hash_locked_and_non_root() -> None:
    text = (ROOT / "packaging" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^ARG PYTHON_IMAGE=python:[\d.]+-slim-\w+@sha256:[0-9a-f]{64}$", text, re.M)
    # Every dependency install from PyPI enforces hashes; only our own wheel is installed bare.
    block = text.replace("\\\n", " ")
    for line in block.splitlines():
        if "pip install" in line and "/tmp/wheels" not in line:  # noqa: S108 - text match
            assert line.count("pip install") == line.count("--require-hashes"), line
    assert "USER 10001:10001" in text
    assert "HEALTHCHECK" in text


def test_postgres_driver_list_is_fully_hashed() -> None:
    text = (ROOT / "packaging" / "docker" / "postgres-driver.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([a-z-]+)==\S+ \\$", text, re.M)
    assert pins == ["psycopg", "psycopg-binary"]
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", text)) >= 3


def test_dockerignore_is_an_allow_list() -> None:
    lines = [
        ln
        for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if ln and not ln.startswith("#")
    ]
    assert lines[0] == "*"
    assert "!src/" in lines


def test_compose_has_no_default_secrets_and_pins_images() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    images = re.findall(r"^\s+image:\s*(\S+)$", text, re.M)
    external = [i for i in images if i != "apiedge:local"]
    assert len(external) == 2
    for image in external:
        assert re.search(r":[\w.-]+@sha256:[0-9a-f]{64}$", image), image
    assert "${POSTGRES_PASSWORD:?" in text
    assert not re.search(r"POSTGRES_PASSWORD:\s*['\"]?[A-Za-z0-9]", text)
    # Published ports bind to localhost only.
    for port in re.findall(r'^\s+- "([^"]+:\d+)"$', text, re.M):
        assert port.startswith("127.0.0.1:"), port


def test_docs_site_zip(tmp_path: Path) -> None:
    site = tmp_path / "site"
    (site / "api").mkdir(parents=True)
    (site / "index.html").write_text("<html></html>", encoding="utf-8")
    (site / "api" / "reference.html").write_text("<html></html>", encoding="utf-8")
    dest = tmp_path / "apiedge-1.0.0-docs.zip"
    assert br.write_docs_zip(site, dest, "apiedge-1.0.0-docs") == 2
    with zipfile.ZipFile(dest) as zf:
        assert sorted(zf.namelist()) == [
            "apiedge-1.0.0-docs/api/reference.html",
            "apiedge-1.0.0-docs/index.html",
        ]
    with pytest.raises(br.ReleaseError):
        br.write_docs_zip(tmp_path / "empty", tmp_path / "x.zip", "x")


def test_build_refuses_a_docs_site_inside_the_cleaned_build_dir(tmp_path: Path) -> None:
    args = br.argparse.Namespace(
        tag=None, out=tmp_path / "out", helm=False, docs_site=br.ROOT / "build" / "site"
    )
    with pytest.raises(br.ReleaseError, match="outside"):
        br.cmd_build(args)
