# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""``apiedge`` command-line interface: init, migrate, run, create-admin, version."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sqlalchemy import select

from apiedge import __version__
from apiedge.config import Settings

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _settings(args: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if getattr(args, "data_dir", None):
        overrides["data_dir"] = Path(args.data_dir)
    if getattr(args, "database_url", None):
        overrides["database_url"] = args.database_url
    return Settings(**overrides)


def _ensure_secret_key(settings: Settings) -> None:
    """Create the secrets-encryption key file unless a key is configured in the environment."""
    from apiedge.security.crypto import ensure_key_file

    if settings.secret_key is None and ensure_key_file(settings.effective_secret_key_file):
        print(f"created secrets key: {settings.effective_secret_key_file} (back it up securely)")


def cmd_init(args: argparse.Namespace) -> int:
    settings = _settings(args)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    print(f"APIEdge {__version__}")
    print(f"data directory : {settings.data_dir}")
    print(f"database       : {_redact(settings.effective_database_url)}")
    _ensure_secret_key(settings)
    if not args.no_migrate:
        return cmd_migrate(args)
    return EXIT_OK


def cmd_migrate(args: argparse.Namespace) -> int:
    from apiedge.db.base import run_migrations

    settings = _settings(args)
    run_migrations(settings.effective_database_url)
    print("database is up to date")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    import uvicorn

    from apiedge.app import create_app

    settings = _settings(args)
    host = args.host or settings.host
    port = args.port or settings.port
    if not args.no_migrate:
        from apiedge.db.base import run_migrations

        run_migrations(settings.effective_database_url)
    _ensure_secret_key(settings)
    local = host in ("127.0.0.1", "::1", "0.0.0.0")  # noqa: S104  # nosec B104 - comparison, not a bind
    url = f"http://{'localhost' if local else host}:{port}/"
    print(f"APIEdge console: {url}")
    if args.open:
        _open_browser_when_ready(url)
    from apiedge.logs import configure_logging, logging_config

    configure_logging(settings.log_level, settings.log_format)
    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        log_level=settings.log_level,
        log_config=logging_config(settings.log_level, settings.log_format),
        server_header=False,  # no product/version disclosure
    )
    return EXIT_OK


def _open_browser_when_ready(url: str) -> None:
    """Open the console in the default browser once the server answers /healthz."""
    import threading
    import time
    import urllib.request
    import webbrowser

    def wait_and_open() -> None:
        for _ in range(60):
            try:
                with urllib.request.urlopen(url + "healthz", timeout=1):  # noqa: S310  # nosec B310
                    break
            except OSError:
                time.sleep(0.5)
        webbrowser.open(url)

    threading.Thread(target=wait_and_open, daemon=True).start()


def cmd_create_admin(args: argparse.Namespace) -> int:
    from apiedge.db.base import make_engine, make_session_factory, run_migrations
    from apiedge.db.models import User
    from apiedge.security.passwords import generate_password, hash_password, password_problems

    settings = _settings(args)
    run_migrations(settings.effective_database_url)
    engine = make_engine(settings.effective_database_url)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            exists = session.scalar(select(User.id).where(User.username == args.username))
            if exists is not None:
                if args.if_missing:
                    print(f"admin user '{args.username}' already exists - nothing to do")
                    return EXIT_OK
                print(f"error: user '{args.username}' already exists", file=sys.stderr)
                return EXIT_ERROR

            generated = False
            if args.generate_password:
                password, generated = generate_password(), True
            elif args.password_stdin:
                password = sys.stdin.readline().rstrip("\r\n")
            elif sys.stdin.isatty():
                password = getpass.getpass(
                    f"Password for '{args.username}' (leave empty to generate one): "
                )
                if not password:
                    password, generated = generate_password(), True
                elif password != getpass.getpass("Repeat password: "):
                    print("error: passwords do not match", file=sys.stderr)
                    return EXIT_ERROR
            else:
                print(
                    "error: use --generate-password or --password-stdin when not on a terminal",
                    file=sys.stderr,
                )
                return EXIT_USAGE

            problems = password_problems(password)
            if problems:
                print("error: password " + "; ".join(problems), file=sys.stderr)
                return EXIT_ERROR

            session.add(
                User(
                    username=args.username,
                    password_hash=hash_password(password),
                    is_superadmin=True,
                    must_change_password=True,
                )
            )
            session.commit()
    finally:
        engine.dispose()

    print(f"created SuperAdmin '{args.username}' (password change required at first login)")
    if generated:
        print("")
        print("  Generated password (shown ONCE - store it safely):")
        # Shown once to the operator by design (T-019); never logged.
        print(f"  {password}")  # codeql[py/clear-text-logging-sensitive-data] T-019
        print("")
    return EXIT_OK


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return EXIT_OK


def _redact(url: str) -> str:
    """Hide the password part of a database URL."""
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        creds, host = rest.rsplit("@", 1)
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return url


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", help="override APIEDGE_DATA_DIR")
    common.add_argument("--database-url", help="override APIEDGE_DATABASE_URL")

    p = argparse.ArgumentParser(prog="apiedge", description="APIEdge API Gateway")
    p.add_argument("--version", action="version", version=f"apiedge {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", parents=[common], help="create the data directory and database")
    s.add_argument("--no-migrate", action="store_true", help="do not run migrations")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("migrate", parents=[common], help="apply database migrations")
    s.set_defaults(func=cmd_migrate)

    s = sub.add_parser("run", parents=[common], help="start the gateway and web console")
    s.add_argument("--host", help="bind address (default APIEDGE_HOST or 127.0.0.1)")
    s.add_argument("--port", type=int, help="port (default APIEDGE_PORT or 8080)")
    s.add_argument("--no-migrate", action="store_true", help="skip automatic migrations")
    s.add_argument("--open", action="store_true", help="open the console in the browser")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("create-admin", parents=[common], help="create a SuperAdmin user")
    s.add_argument("--username", default="admin")
    g = s.add_mutually_exclusive_group()
    g.add_argument(
        "--generate-password",
        action="store_true",
        help="generate a strong password and print it once",
    )
    g.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    s.add_argument(
        "--if-missing",
        action="store_true",
        help="succeed without changes if the user already exists",
    )
    s.set_defaults(func=cmd_create_admin)

    s = sub.add_parser("version", help="print the version")
    s.set_defaults(func=cmd_version)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rc: int = args.func(args)
    return rc


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
