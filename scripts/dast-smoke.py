# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""DAST-style smoke pass against a running APIEdge instance (T-018).

Black-box checks over HTTP, standard library only, so it runs in CI and on an operator's
machine without extra dependencies:

    python scripts/dast-smoke.py --console http://127.0.0.1:8080 \
        --gateway http://127.0.0.1:8081 --username admin --password-file pw.txt

Covered: security headers and CSP on the console, API and gateway; no server banner; API docs
hidden in production; CORS closed to unknown origins; session cookie flags; CSRF (missing token,
foreign Origin, cross-site "simple" login request); request body limits (admin API and gateway);
error documents without stack traces or echoed input; unsupported methods; the SSRF guard on
upstream URLs; gateway path normalisation; login throttling (last, it blocks the client IP for a
minute). Exit code 0 when every check passes, 1 otherwise; one line per check.

The instance must run in production mode. The account must be a SuperAdmin; a pending first-login
password change is completed with a generated password that is printed nowhere.
"""

from __future__ import annotations

import argparse
import http.client
import json
import secrets
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

FORBIDDEN_TEXT = ("Traceback", 'File "', "sqlalchemy", "pydantic_core", "uvicorn")
RESULTS: list[tuple[bool, str]] = []


@dataclass
class Response:
    status: int
    headers: http.client.HTTPMessage
    body: bytes
    cookies: list[str] = field(default_factory=list)

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    def json(self) -> Any:
        return json.loads(self.body or b"null")


def request(
    base: str,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> Response:
    url = urllib.parse.urlsplit(base)
    conn_cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(url.hostname or "127.0.0.1", url.port, timeout=30)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return Response(resp.status, resp.headers, data, resp.headers.get_all("set-cookie") or [])
    finally:
        conn.close()


def send_json(
    base: str, method: str, path: str, payload: Any, headers: dict[str, str] | None = None
) -> Response:
    h = {"Content-Type": "application/json", **(headers or {})}
    return request(base, method, path, headers=h, body=json.dumps(payload).encode())


def check(ok: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((ok, name))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    return ok


def no_leak(resp: Response) -> bool:
    text = resp.body.decode("utf-8", "replace")
    return not any(marker in text for marker in FORBIDDEN_TEXT)


# --------------------------------------------------------------------------------- checks


def check_headers(console: str) -> None:
    for path in ("/", "/api/v1/auth/me", "/healthz", "/api/v1/nope"):
        r = request(console, "GET", path)
        h = {k.lower(): v for k, v in r.headers.items()}
        csp = h.get("content-security-policy", "")
        check(h.get("x-content-type-options") == "nosniff", f"nosniff on {path}")
        check(h.get("x-frame-options", "").upper() == "DENY", f"X-Frame-Options DENY on {path}")
        check("frame-ancestors 'none'" in csp, f"CSP frame-ancestors on {path}", csp)
        check(
            "default-src" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp,
            f"strict CSP on {path}",
            csp,
        )
        check(bool(h.get("referrer-policy")), f"Referrer-Policy on {path}")
        check("server" not in h and "x-powered-by" not in h, f"no server banner on {path}")
        if path.startswith("/api"):
            check("no-store" in h.get("cache-control", ""), f"Cache-Control no-store on {path}")


def check_docs_hidden(console: str) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = request(console, "GET", path)
        check(
            r.status != 200 or b"openapi" not in r.body.lower()[:200],
            f"{path} not served in production",
            str(r.status),
        )


def check_cors(console: str) -> None:
    r = request(
        console,
        "OPTIONS",
        "/api/v1/auth/login",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    check(
        "access-control-allow-origin" not in {k.lower() for k in r.headers},
        "CORS preflight from an unknown origin is not allowed",
    )
    r = request(console, "GET", "/healthz", headers={"Origin": "https://evil.example"})
    check(r.header("access-control-allow-origin") == "", "no CORS headers for unknown origin")


def check_errors(console: str) -> None:
    r = request(console, "GET", "/api/v1/does-not-exist")
    check(r.status == 404 and no_leak(r), "unknown API path: 404 without internals")
    marker = "<script>alert(1)</script>"
    r = request(
        console,
        "POST",
        "/api/v1/auth/login",
        headers={"Content-Type": "application/json"},
        body=b'{"username": "' + marker.encode() + b'", "password": ',
    )
    check(
        r.status == 422 and no_leak(r) and marker.encode() not in r.body,
        "malformed JSON: 422 without echoed input or internals",
        str(r.status),
    )
    r = send_json(console, "POST", "/api/v1/auth/login", {"username": marker, "extra": marker})
    check(
        r.status == 422 and marker.encode() not in r.body,
        "validation error does not echo input",
        str(r.status),
    )
    r = request(console, "TRACE", "/api/v1/auth/me")
    check(r.status in (405, 404) and no_leak(r), "TRACE refused", str(r.status))


def check_login_csrf(console: str) -> None:
    # A cross-site form can only send "simple" content types; the API must not accept them.
    r = request(
        console,
        "POST",
        "/api/v1/auth/login",
        headers={"Content-Type": "text/plain"},
        body=b'{"username":"x","password":"y"}',
    )
    check(
        r.status in (415, 422) and not any("apiedge_session" in c for c in r.cookies),
        "cross-site simple-request login refused",
        str(r.status),
    )


def sign_in(console: str, username: str, password: str) -> dict[str, str]:
    """Sign in with cookies; returns the cookie jar as a dict. Completes a pending change."""
    r = send_json(
        console, "POST", "/api/v1/auth/login", {"username": username, "password": password}
    )
    if r.status != 200:
        raise SystemExit(f"sign-in failed with HTTP {r.status}; cannot continue")
    jar: dict[str, str] = {}
    flags: dict[str, str] = {}
    for raw in r.cookies:
        c: SimpleCookie = SimpleCookie()
        c.load(raw)
        for name, morsel in c.items():
            jar[name] = morsel.value
            flags[name] = raw.lower()
    for name in ("apiedge_session", "apiedge_refresh"):
        raw = flags.get(name, "")
        check(
            "httponly" in raw and "samesite=strict" in raw,
            f"{name} cookie is HttpOnly and SameSite=Strict",
            raw,
        )
    check("path=/api" in flags.get("apiedge_session", ""), "session cookie scoped to /api")
    check("path=/api/v1/auth" in flags.get("apiedge_refresh", ""), "refresh cookie scoped to auth")
    csrf = flags.get("apiedge_csrf", "")
    check(
        bool(csrf) and "httponly" not in csrf and "samesite=strict" in csrf,
        "CSRF cookie readable by the console, SameSite=Strict",
        csrf,
    )
    if r.json().get("must_change_password"):
        new = "Dast-" + secrets.token_urlsafe(18)
        r2 = send_json(
            console,
            "POST",
            "/api/v1/auth/change-password",
            {"current_password": password, "new_password": new},
            _cookie_headers(jar, csrf=True),
        )
        if r2.status != 200:
            raise SystemExit(f"password change failed with HTTP {r2.status}")
        for raw in r2.cookies:
            c2: SimpleCookie = SimpleCookie()
            c2.load(raw)
            jar.update({k: m.value for k, m in c2.items()})
    return jar


def _cookie_headers(
    jar: dict[str, str], *, csrf: bool, origin: str | None = None
) -> dict[str, str]:
    h = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())}
    if csrf:
        h["X-CSRF-Token"] = jar.get("apiedge_csrf", "")
    if origin:
        h["Origin"] = origin
    return h


def check_csrf(console: str, jar: dict[str, str]) -> None:
    payload = {"slug": "dast-csrf", "name": "CSRF probe"}
    r = send_json(console, "POST", "/api/v1/tenants", payload, _cookie_headers(jar, csrf=False))
    check(r.status == 403, "cookie request without CSRF token refused", str(r.status))
    r = send_json(
        console,
        "POST",
        "/api/v1/tenants",
        payload,
        _cookie_headers(jar, csrf=True, origin="https://evil.example"),
    )
    check(r.status == 403, "cookie request from a foreign Origin refused", str(r.status))
    bad = dict(jar, apiedge_csrf="forged")
    h = _cookie_headers(bad, csrf=False)
    h["X-CSRF-Token"] = "different"
    r = send_json(console, "POST", "/api/v1/tenants", payload, h)
    check(r.status == 403, "mismatched CSRF token refused", str(r.status))


def check_body_limit(base: str, path: str, limit: int, name: str, headers: dict[str, str]) -> None:
    body = b"{" + b" " * (limit + 1024) + b"}"
    try:
        r = request(
            base, "POST", path, headers={"Content-Type": "application/json", **headers}, body=body
        )
        check(r.status == 413 and no_leak(r), f"{name} body limit answers 413", str(r.status))
    except (ConnectionError, http.client.HTTPException) as exc:
        # Closing the connection early is also an acceptable refusal of an oversized body.
        check(True, f"{name} body limit (connection closed: {type(exc).__name__})")


def check_ssrf(console: str, jar: dict[str, str]) -> tuple[int, str] | None:
    """SSRF probes in a scratch tenant; leaves one published API for the gateway checks."""
    h = _cookie_headers(jar, csrf=True)
    slug = "dast-" + secrets.token_hex(3)
    r = send_json(console, "POST", "/api/v1/tenants", {"slug": slug, "name": "DAST"}, h)
    if not check(r.status == 201, "SuperAdmin can create a scratch tenant", str(r.status)):
        return None
    tenant = r.json()["id"]
    r = send_json(console, "POST", f"/api/v1/tenants/{tenant}/products", {"name": "DAST"}, h)
    if not check(r.status == 201, "scratch product created", str(r.status)):
        return None
    product = r.json()["id"]
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "file:///etc/passwd",
        "http://0x7f000001/",
    ):
        body = {
            "name": "Probe",
            "base_path": "/probe-" + secrets.token_hex(3),
            "upstreams": [{"url": url}],
        }
        r = send_json(console, "POST", f"/api/v1/tenants/{tenant}/products/{product}/apis", body, h)
        check(
            r.status in (400, 422) and no_leak(r),
            f"SSRF guard refuses upstream {url}",
            str(r.status),
        )
    base = f"/api/v1/tenants/{tenant}/products/{product}"
    body = {
        "name": "Echo",
        "base_path": "/dast",
        "upstreams": [{"url": "https://example.com"}],
        "routes": [{"methods": ["GET", "POST"], "path": "/*"}],
    }
    r = send_json(console, "POST", base + "/apis", body, h)
    if not check(r.status == 201, "public upstream accepted", r.body.decode()[:200]):
        return tenant, slug
    api = r.json()["id"]
    for path in (f"/apis/{api}/lifecycle", "/lifecycle"):
        r = send_json(console, "POST", base + path, {"lifecycle": "published"}, h)
        check(r.status == 200, f"published {path}", r.body.decode()[:200])
    return tenant, slug


def remove_tenant(console: str, jar: dict[str, str], tenant: int) -> None:
    r = request(
        console, "DELETE", f"/api/v1/tenants/{tenant}", headers=_cookie_headers(jar, csrf=True)
    )
    check(r.status == 204, "scratch tenant removed", str(r.status))


def check_gateway(gateway: str) -> None:
    r = request(gateway, "GET", "/no-such-tenant/no-such-api")
    check(r.status == 404 and no_leak(r), "gateway unknown route: 404 without internals")
    check("server" not in {k.lower() for k in r.headers}, "gateway sends no server banner")
    check(r.header("x-content-type-options") == "nosniff", "gateway nosniff")
    r = request(gateway, "GET", "/t/a/%2e%2e/admin")
    check(r.status in (400, 404) and no_leak(r), "gateway refuses dot-segment paths", str(r.status))


def check_login_throttle(console: str) -> None:
    statuses = []
    # A rotating X-Forwarded-For must not reset the throttle: the scanning host is not a
    # trusted proxy (run the instance with APIEDGE_TRUSTED_PROXIES unset to an empty value).
    for i in range(60):
        r = send_json(
            console,
            "POST",
            "/api/v1/auth/login",
            {"username": "dast-unknown", "password": secrets.token_urlsafe(16)},
            {"X-Forwarded-For": f"203.0.113.{i}"},
        )
        statuses.append(r.status)
        if r.status == 429:
            break
    check(
        429 in statuses and 200 not in statuses,
        "login throttled per client, forwarded headers ignored (429)",
        ",".join(map(str, sorted(set(statuses)))),
    )
    check(all(s in (401, 429) for s in statuses), "failed sign-ins look alike (401)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    p.add_argument("--console", default="http://127.0.0.1:8080")
    p.add_argument("--gateway", default="")
    p.add_argument("--username", default="admin")
    p.add_argument("--password-file", type=Path, required=True)
    p.add_argument("--max-body", type=int, default=2 * 1024 * 1024)
    p.add_argument("--gateway-max-body", type=int, default=10 * 1024 * 1024)
    args = p.parse_args(argv)
    password = args.password_file.read_text(encoding="utf-8").strip()

    check_headers(args.console)
    check_docs_hidden(args.console)
    check_cors(args.console)
    check_errors(args.console)
    check_login_csrf(args.console)
    jar = sign_in(args.console, args.username, password)
    check_csrf(args.console, jar)
    check_body_limit(
        args.console, "/api/v1/tenants", args.max_body, "admin API", _cookie_headers(jar, csrf=True)
    )
    scratch = check_ssrf(args.console, jar)
    if args.gateway:
        check_gateway(args.gateway)
        if scratch:
            time.sleep(2)  # allow the gateway to load the published API
            check_body_limit(
                args.gateway, f"/{scratch[1]}/dast/upload", args.gateway_max_body, "gateway", {}
            )
    if scratch:
        remove_tenant(args.console, jar, scratch[0])
    check_login_throttle(args.console)

    failed = [name for ok, name in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
