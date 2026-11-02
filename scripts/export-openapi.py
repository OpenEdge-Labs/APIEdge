#!/usr/bin/env python3
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Export the Admin API reference from the application itself.

Writes two committed files from ``create_app().openapi()``:

* ``docs/api/openapi.json`` - the OpenAPI 3 document, as served at ``/api/v1/openapi.json``;
* ``docs/api/reference.md`` - a readable reference rendered from it (operations by tag, the
  permission each one needs, parameters, request and response bodies, and every schema). The
  documentation site turns it into static HTML.

``--check`` writes nothing and fails when either file is out of date; CI and the test suite run
it, so the reference cannot drift from the code.

Usage:  python scripts/export-openapi.py [--check]
"""

from __future__ import annotations

import argparse
import html
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "api"
JSON_FILE = OUT_DIR / "openapi.json"
MD_FILE = OUT_DIR / "reference.md"

SCOPE_TEXT = {
    "public": "none (no sign-in)",
    "signed-in": "any signed-in user",
    "platform": "`{permission}` (platform permission: SuperAdmins only)",
    "tenant": "`{permission}` in the tenant",
    "product": "`{permission}` in the tenant, or for the product concerned (product-scoped grant)",
}
METHODS = ("get", "post", "put", "patch", "delete")


def build_spec() -> dict[str, Any]:
    """The OpenAPI document of a production-mode app with throw-away data and settings."""
    from apiedge.app import create_app
    from apiedge.config import Settings

    with tempfile.TemporaryDirectory(prefix="apiedge-openapi-") as tmp:
        settings = Settings(
            env="production",
            data_dir=Path(tmp),
            secret_key="A" * 43,  # placeholder: never used to encrypt anything
            _env_file=None,
        )
        app = create_app(settings)
        spec: dict[str, Any] = app.openapi()
        app.state.engine.dispose()
    return spec


def _cell(text: object) -> str:
    """Text safe inside a Markdown table cell (no raw HTML, no pipes, one line)."""
    return html.escape(" ".join(str(text).split()), quote=False).replace("|", "&#124;")


def _code(value: object) -> str:
    """Inline code that is safe inside a table cell (a pipe would end the cell)."""
    text = _cell(value)
    for char in "\\`*_[]{}":  # no Markdown inside the code element
        text = text.replace(char, f"&#{ord(char)};")
    return f"<code>{text}</code>"


def _num(value: object) -> object:
    return int(value) if isinstance(value, float) and value.is_integer() else value


def _ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def _schema_link(name: str) -> str:
    return f"[{name}](#schema-{name.lower()})"


def type_of(schema: dict[str, Any]) -> str:
    """A short Markdown description of a JSON Schema type."""
    if "$ref" in schema:
        return _schema_link(_ref_name(schema["$ref"]))
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            parts = [type_of(s) for s in schema[key]]
            return (" and " if key == "allOf" else " or ").join(dict.fromkeys(parts))
    if "const" in schema:
        return _code(json.dumps(schema["const"]))
    kind = schema.get("type")
    if isinstance(kind, list):
        return " or ".join(kind)
    if kind == "array":
        return f"array of {type_of(schema.get('items', {}))}"
    if kind == "object" and isinstance(schema.get("additionalProperties"), dict):
        return f"map of {type_of(schema['additionalProperties'])}"
    text = str(kind or "any")
    if "format" in schema:
        text += f" ({schema['format']})"
    if "enum" in schema:
        text += ": " + ", ".join(_code(json.dumps(v)) for v in schema["enum"])
    return text


def _constraints(schema: dict[str, Any]) -> str:
    notes = []
    for key, label in (
        ("minLength", "min length"),
        ("maxLength", "max length"),
        ("minimum", "min"),
        ("maximum", "max"),
        ("exclusiveMinimum", "greater than"),
        ("exclusiveMaximum", "less than"),
        ("minItems", "min items"),
        ("maxItems", "max items"),
        ("pattern", "pattern"),
    ):
        if key in schema:
            value = schema[key]
            notes.append(
                f"{label} {_code(value)}" if key == "pattern" else f"{label} {_num(value)}"
            )
    if "default" in schema:
        notes.append(f"default {_code(json.dumps(schema['default']))}")
    return "; ".join(notes)


def _body_types(content: dict[str, Any]) -> str:
    parts = []
    for media, body in content.items():
        schema = body.get("schema")
        parts.append(_code(media) + (f": {type_of(schema)}" if schema else ""))
    return "<br>".join(parts) if parts else "-"


def render_reference(spec: dict[str, Any]) -> str:
    """Render the OpenAPI document as one Markdown page."""
    out = [
        "<!-- Copyright 2026 OpenEdge Labs",
        "     SPDX-License-Identifier: Apache-2.0",
        "     GENERATED by scripts/export-openapi.py from the application - do not edit. -->",
        "",
        "# Admin API reference",
        "",
        f"{spec['info']['title']}, version `{spec['info']['version']}`, OpenAPI "
        f"`{spec['openapi']}`. The machine-readable document is [openapi.json](openapi.json) "
        "(also served by every installation at `/api/v1/openapi.json`). How to authenticate, "
        "CSRF, errors and conventions are explained in the [Admin API guide](index.md).",
        "",
        "**Access** names the permission an operation needs. Tenant routes answer `404` when the "
        "caller does not belong to the tenant, and `403 permission_denied` when the permission is "
        "missing. Some operations check more inside (for example the product a request touches); "
        "their descriptions say so.",
        "",
    ]
    by_tag: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
    for path, item in spec["paths"].items():
        for method in METHODS:
            if method in item:
                op = item[method]
                by_tag.setdefault((op.get("tags") or ["other"])[0], []).append((method, path, op))

    out += ["## Operations", ""]
    for tag, ops in by_tag.items():
        out += [f"| {tag} | |", "|---|---|"]
        for method, path, op in ops:
            out.append(f"| `{method.upper()} {path}` | {_cell(op.get('summary', ''))} |")
        out.append("")

    for tag, ops in by_tag.items():
        out += [f"## {tag}", ""]
        for method, path, op in ops:
            out += [f"### {method.upper()} {path}", ""]
            if op.get("summary"):
                out += [f"{op['summary']}.", ""]
            access = op.get("x-apiedge-access", {"scope": "public"})
            scope_text = SCOPE_TEXT[access["scope"]].format(permission=access.get("permission"))
            out += [f"**Access:** {scope_text}", ""]
            if op.get("description"):
                out += [html.escape(op["description"].strip(), quote=False), ""]
            params = op.get("parameters", [])
            if params:
                out += [
                    "| Parameter | In | Type | Required | Notes |",
                    "|---|---|---|---|---|",
                ]
                for p in params:
                    schema = p.get("schema", {})
                    notes = "; ".join(
                        x for x in (_cell(p.get("description", "")), _constraints(schema)) if x
                    )
                    out.append(
                        f"| `{p['name']}` | {p['in']} | {type_of(schema)} | "
                        f"{'yes' if p.get('required') else 'no'} | {notes} |"
                    )
                out.append("")
            body = op.get("requestBody")
            if body:
                body_required = " (required)" if body.get("required") else ""
                out += [
                    f"**Request body{body_required}:** {_body_types(body.get('content', {}))}",
                    "",
                ]
            responses = op.get("responses", {})
            if responses:
                out += ["| Status | Meaning | Body |", "|---|---|---|"]
                for status, resp in responses.items():
                    out.append(
                        f"| {status} | {_cell(resp.get('description', ''))} | "
                        f"{_body_types(resp.get('content', {}))} |"
                    )
                out.append("")

    schemas = spec.get("components", {}).get("schemas", {})
    if schemas:
        out += ["## Schemas", ""]
        for name, schema in schemas.items():
            out += [f"### {name} {{#schema-{name.lower()}}}", ""]
            if schema.get("description"):
                out += [_cell(schema["description"]), ""]
            props = schema.get("properties")
            if props:
                required = set(schema.get("required", []))
                out += ["| Field | Type | Required | Notes |", "|---|---|---|---|"]
                for field, sub in props.items():
                    notes = "; ".join(
                        x for x in (_cell(sub.get("description", "")), _constraints(sub)) if x
                    )
                    out.append(
                        f"| `{field}` | {type_of(sub)} | {'yes' if field in required else 'no'} "
                        f"| {notes} |"
                    )
                out.append("")
            else:
                out += [f"Type: {type_of(schema)}", ""]
    return "\n".join(out).rstrip("\n") + "\n"


def render_json(spec: dict[str, Any]) -> str:
    return json.dumps(spec, indent=2, ensure_ascii=True) + "\n"


def outputs() -> dict[Path, str]:
    spec = build_spec()
    return {JSON_FILE: render_json(spec), MD_FILE: render_reference(spec)}


def stale_files() -> list[Path]:
    """Committed files that differ from a fresh export."""
    return [
        path
        for path, text in outputs().items()
        if not path.exists() or path.read_text(encoding="utf-8") != text
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed files are stale")
    args = ap.parse_args()
    if args.check:
        stale = stale_files()
        for path in stale:
            print(f"error: {path.relative_to(ROOT).as_posix()} is out of date")
        if stale:
            print("run: python scripts/export-openapi.py")
            return 1
        print("Admin API reference is up to date")
        return 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path, text in outputs().items():
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
