# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Documentation drift checks (T-017): settings, links and the generated Admin API reference."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

from apiedge.config import Settings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
CONFIG_GUIDE = DOCS / "admin-guide" / "configuration.md"

# APIEDGE_* names in the docs that are not ``Settings`` fields, and where they belong.
NON_SETTINGS = {
    "APIEDGE_ADMIN_USER",  # container entry point
    "APIEDGE_ADMIN_PASSWORD_FILE",  # container entry point
    "APIEDGE_WITH_POSTGRES",  # former Docker build argument (removed in T-033; history only)
    "APIEDGE_CONSOLE_PORT",  # docker-compose.yml port mapping
    "APIEDGE_GATEWAY_PUBLISH_PORT",  # docker-compose.yml port mapping
    "APIEDGE_RELEASE_GPG_KEY",  # release workflow secret
    "APIEDGE_RELEASE_GPG_PASSPHRASE",  # release workflow secret
    "APIEDGE_PUBLISH_RELEASE",  # release workflow variable
}
LINK = re.compile(r"\]\(([^)\s]+)\)")


def _env_names() -> set[str]:
    return {f"APIEDGE_{name.upper()}" for name in Settings.model_fields}


def _markdown_files() -> list[Path]:
    files = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "THIRD_PARTY_LICENSES.md"]
    return files + sorted(DOCS.rglob("*.md"))


def test_every_setting_is_documented() -> None:
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    guide = CONFIG_GUIDE.read_text(encoding="utf-8")
    missing_example = sorted(n for n in _env_names() if n not in env_example)
    missing_guide = sorted(n for n in _env_names() if f"`{n}`" not in guide)
    assert not missing_example, f"add to .env.example: {missing_example}"
    assert not missing_guide, f"add to docs/admin-guide/configuration.md: {missing_guide}"


def test_documented_settings_exist() -> None:
    known = _env_names() | NON_SETTINGS
    unknown: dict[str, set[str]] = {}
    for path in [*_markdown_files(), ROOT / ".env.example"]:
        text = path.read_text("utf-8")
        for name, wildcard in re.findall(r"(APIEDGE_[A-Z][A-Z0-9_]*[A-Z0-9])(_\*)?", text):
            if wildcard:  # a group such as APIEDGE_INSPECTOR_*
                if not any(k.startswith(name + "_") for k in known):
                    unknown.setdefault(name + "_*", set()).add(path.relative_to(ROOT).as_posix())
            elif name not in known:
                unknown.setdefault(name, set()).add(path.relative_to(ROOT).as_posix())
    assert not unknown, f"documented but not a setting: {unknown}"


def test_relative_links_resolve() -> None:
    broken = []
    for path in _markdown_files():
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"```.*?```", "", text, flags=re.S)  # code blocks are not links
        for target in LINK.findall(text):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue  # external URL or same-page anchor (mkdocs --strict checks anchors)
            file_part = target.split("#", 1)[0]
            if not (path.parent / file_part).exists():
                broken.append(f"{path.relative_to(ROOT).as_posix()}: {target}")
    assert not broken, broken


def test_every_doc_page_is_in_the_site_navigation() -> None:
    nav = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    pages = sorted(p.relative_to(DOCS).as_posix() for p in DOCS.rglob("*.md"))
    assert [p for p in pages if f": {p}" not in nav] == []


def _export_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "apiedge_export_openapi", ROOT / "scripts" / "export-openapi.py"
    )
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def export() -> ModuleType:
    return _export_script()


def test_api_reference_is_up_to_date(export: ModuleType) -> None:
    stale = export.stale_files()
    assert not stale, "run: python scripts/export-openapi.py"


def test_every_operation_declares_its_access(export: ModuleType) -> None:
    spec = export.build_spec()
    public = {"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout"}
    public |= {"/healthz", "/readyz"}
    for path, item in spec["paths"].items():
        for method, op in item.items():
            access = op.get("x-apiedge-access")
            assert access, f"{method} {path}"
            if path in public:
                assert access["scope"] == "public", f"{method} {path}"
            elif "{tenant_id}" in path:
                assert access["scope"] in ("tenant", "product", "platform"), f"{method} {path}"
                assert access["permission"], f"{method} {path}"
            else:
                assert access["scope"] in ("signed-in", "platform"), f"{method} {path}"


def test_reference_rendering_escapes_markup(export: ModuleType) -> None:
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1"},
        "paths": {
            "/x": {
                "get": {
                    "tags": ["t"],
                    "summary": "S",
                    "description": "<script>alert(1)</script>",
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "schema": {"type": "string", "pattern": "a|b_*"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "components": {"schemas": {"A": {"properties": {"f": {"$ref": "#/components/schemas/B"}}}}},
    }
    md = export.render_reference(spec)
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    assert "<code>a&#124;b&#95;&#42;</code>" in md
    assert "[B](#schema-b)" in md
    assert "### A {#schema-a}" in md
