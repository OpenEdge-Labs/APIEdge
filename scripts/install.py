#!/usr/bin/env python3
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""APIEdge one-click installer (shared by install.bat, install.command and install.sh).

Uses only the Python standard library. Steps:

  1. check Python (3.10 - 3.12)
  2. create (or repair) a virtual environment
  3. install hash-locked dependencies from PyPI  (requirements/*.lock, --require-hashes)
  4. install APIEdge itself from this checkout
  5. run database migrations
  6. create the first SuperAdmin (prompted, or a generated password shown once)
  7. optionally create desktop / start-menu shortcuts
  8. start APIEdge and open the console in the browser

Re-running it upgrades/repairs an existing install (idempotent). ``--uninstall``
removes the environment and shortcuts; ``--purge-data`` also deletes the database.

Examples:
  python scripts/install.py                       interactive install + start
  python scripts/install.py --yes --smoke-test    unattended install, health check, stop (CI)
  python scripts/install.py --local --dev --no-start   developer setup in ./.venv
  python scripts/install.py --uninstall
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess  # nosec B404 - runs pip/apiedge with argument lists, never a shell
import sys
import time
import urllib.error
import urllib.request
import venv
import webbrowser
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import TextIO

MIN_PY = (3, 10)
MAX_PY = (3, 12)
APP = "APIEdge"
ROOT = Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements"
PYTHON_DOWNLOAD = "https://www.python.org/downloads/"

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"


SERVICE_NAME = "apiedge"
_LOG: TextIO | None = None


# ---------------------------------------------------------------- helpers
def redact(text: str) -> str:
    """Hide credentials in URLs (e.g. --proxy http://user:pass@host)."""
    return re.sub(r"://[^/@\s]+@", "://***@", text)


def say(msg: str) -> None:
    print(msg, flush=True)
    if _LOG is not None:
        _LOG.write(redact(msg) + "\n")
        _LOG.flush()


def open_log(data_dir: Path) -> Path:
    """Append-only install log in the data dir. Secrets (admin password) are never logged."""
    global _LOG
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "install.log"
    _LOG = path.open("a", encoding="utf-8")
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _LOG.write(f"\n===== {stamp} install.py {redact(' '.join(sys.argv[1:]))}\n")
    return path


def close_log() -> None:
    global _LOG
    if _LOG is not None:
        _LOG.close()
        _LOG = None


def step(n: int, total: int, msg: str) -> None:
    say(f"\n[{n}/{total}] {msg}")


def fail(msg: str, code: int = 1) -> None:
    say(f"\nERROR: {msg}")
    sys.exit(code)


def ask_yes(question: str, default: bool, assume_yes: bool) -> bool:
    if assume_yes or not sys.stdin.isatty():
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def run(cmd: list[str], env: dict[str, str] | None = None, log_output: bool = True) -> None:
    """Run a command; stream its output to the console and (unless disabled) the install log."""
    say("  $ " + subprocess.list2cmdline(cmd))
    if log_output and _LOG is not None:
        proc = subprocess.Popen(  # nosec B603
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.stdout is None:  # pragma: no cover - PIPE was requested
            fail("could not capture command output")
            return
        for line in proc.stdout:
            print(line, end="", flush=True)
            _LOG.write(redact(line))
        returncode = proc.wait()
    else:
        if _LOG is not None:
            _LOG.write("  (output not logged: may contain a secret)\n")
        returncode = subprocess.run(cmd, env=env, check=False).returncode  # nosec B603
    if returncode != 0:
        fail(f"command failed with exit code {returncode}: {' '.join(cmd[:2])}")


def default_data_dir() -> Path:
    """Mirror platformdirs.user_data_path('APIEdge', 'APIEdge') without importing it."""
    if IS_WIN:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP / APP
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / APP
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if IS_WIN else "bin/python")


def venv_apiedge(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/apiedge.exe" if IS_WIN else "bin/apiedge")


def check_python() -> None:
    v = sys.version_info[:2]
    if v < MIN_PY or v > MAX_PY:
        fail(
            f"APIEdge needs Python {MIN_PY[0]}.{MIN_PY[1]} to {MAX_PY[0]}.{MAX_PY[1]}, "
            f"but this is Python {v[0]}.{v[1]} ({sys.executable}).\n"
            f"Install a supported version from {PYTHON_DOWNLOAD} and run the installer again.",
            code=3,
        )
    say(f"  Python {sys.version.split()[0]} at {sys.executable}")


def venv_is_healthy(venv_dir: Path) -> bool:
    py = venv_python(venv_dir)
    if not py.exists():
        return False
    probe = subprocess.run(  # nosec B603
        [str(py), "-c", "import sys, pip; print(sys.version_info[:2])"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and probe.stdout.strip() == str(tuple(sys.version_info[:2]))


# ---------------------------------------------------------------- shortcuts
def shortcut_paths() -> list[Path]:
    home = Path.home()
    if IS_WIN:
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        return [
            appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / f"{APP}.lnk",
            home / "Desktop" / f"{APP}.lnk",
        ]
    if IS_MAC:
        return [home / "Desktop" / f"{APP}.command"]
    return [
        home / ".local" / "share" / "applications" / "apiedge.desktop",
        home / "Desktop" / "apiedge.desktop",
    ]


def _windows_lnk(path: Path, exe: Path, args: list[str], minimized: bool = False) -> None:
    # Values are passed via environment variables, never interpolated into the script.
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:AE_LNK);"
        "$s.TargetPath=$env:AE_EXE;$s.Arguments=$env:AE_ARGS;$s.WindowStyle=[int]$env:AE_WS;"
        "$s.WorkingDirectory=$env:AE_WD;$s.Description='APIEdge API Gateway';$s.Save()"
    )
    env = dict(
        os.environ,
        AE_LNK=str(path),
        AE_EXE=str(exe),
        AE_ARGS=subprocess.list2cmdline(args),
        AE_WD=str(Path.home()),
        AE_WS="7" if minimized else "1",
    )
    subprocess.run(  # nosec B603 B607
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env, check=False
    )


def create_shortcuts(venv_dir: Path, run_args: list[str]) -> None:
    exe = venv_apiedge(venv_dir)
    args = ["run", "--open", *run_args]
    for path in shortcut_paths():
        if path.parent.name == "Desktop" and not path.parent.is_dir():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if IS_WIN:
            _windows_lnk(path, exe, args)
        elif IS_MAC:
            quoted = " ".join(_sh_quote(a) for a in [str(exe), *args])
            path.write_text(f"#!/bin/sh\nexec {quoted}\n", encoding="utf-8")
            path.chmod(0o755)
        else:
            exec_line = " ".join(_desktop_quote(a) for a in [str(exe), *args])
            path.write_text(
                "[Desktop Entry]\nType=Application\nName=APIEdge\n"
                "Comment=APIEdge API Gateway\n"
                f"Exec={exec_line}\nTerminal=true\nCategories=Development;Network;\n",
                encoding="utf-8",
            )
            path.chmod(0o755)
        if path.exists():
            say(f"  shortcut: {path}")


def remove_shortcuts() -> None:
    for path in shortcut_paths():
        if path.exists():
            path.unlink()
            say(f"  removed {path}")


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _desktop_quote(s: str) -> str:
    if all(c.isalnum() or c in "/._-" for c in s):
        return s
    return (
        '"'
        + s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        + '"'
    )


# ---------------------------------------------------------------- service (start at logon)
def service_file() -> Path:
    home = Path.home()
    if IS_WIN:
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        startup = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        return startup / f"{APP}.lnk"
    if IS_MAC:
        return home / "Library" / "LaunchAgents" / "com.apiedge.gateway.plist"
    return home / ".config" / "systemd" / "user" / f"{SERVICE_NAME}.service"


def systemd_unit(exe: PurePath, args: list[str]) -> str:
    cmd = " ".join(_desktop_quote(a) for a in [str(exe), "run", "--no-migrate", *args])
    return (
        "[Unit]\nDescription=APIEdge API Gateway\nAfter=network-online.target\n\n"
        f"[Service]\nExecStart={cmd}\nRestart=on-failure\nRestartSec=5\n\n"
        "[Install]\nWantedBy=default.target\n"
    )


def launchd_plist(exe: PurePath, args: list[str], log_dir: PurePath) -> str:
    items = "".join(
        f"    <string>{html.escape(a)}</string>\n" for a in [str(exe), "run", "--no-migrate", *args]
    )
    log = html.escape(str(log_dir / "apiedge.log"))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        "  <key>Label</key><string>com.apiedge.gateway</string>\n"
        f"  <key>ProgramArguments</key><array>\n{items}  </array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        f"  <key>StandardOutPath</key><string>{log}</string>\n"
        f"  <key>StandardErrorPath</key><string>{log}</string>\n"
        "</dict></plist>\n"
    )


def register_service(venv_dir: Path, data_dir: Path, args: list[str]) -> bool:
    """Start APIEdge at logon (per user, no admin rights). Returns True if it is now running."""
    exe = venv_apiedge(venv_dir)
    path = service_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    if IS_WIN:
        _windows_lnk(path, exe, ["run", "--no-migrate", *args], minimized=True)
        say(f"  registered: {path} (starts at next logon)")
        return False
    if IS_MAC:
        path.write_text(launchd_plist(exe, args, data_dir), encoding="utf-8")
        subprocess.run(  # nosec B603 B607
            ["launchctl", "unload", str(path)], check=False, capture_output=True
        )
        rc = subprocess.run(["launchctl", "load", "-w", str(path)], check=False)  # nosec B603 B607
        say(f"  registered launchd agent: {path}")
        return rc.returncode == 0
    path.write_text(systemd_unit(exe, args), encoding="utf-8")
    if shutil.which("systemctl") is None:
        say(f"  wrote {path}, but systemctl is not available - start APIEdge manually")
        return False
    unit = f"{SERVICE_NAME}.service"
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)  # nosec B603 B607
    subprocess.run(["systemctl", "--user", "enable", unit], check=False)  # nosec B603 B607
    rc = subprocess.run(["systemctl", "--user", "restart", unit], check=False)  # nosec B603 B607
    say(f"  registered systemd user service: {path}")
    return rc.returncode == 0


def unregister_service() -> None:
    path = service_file()
    if not path.exists():
        return
    if IS_MAC:
        subprocess.run(["launchctl", "unload", "-w", str(path)], check=False)  # nosec B603 B607
    elif not IS_WIN and shutil.which("systemctl"):
        subprocess.run(  # nosec B603 B607
            ["systemctl", "--user", "disable", "--now", f"{SERVICE_NAME}.service"], check=False
        )
    path.unlink()
    say(f"  removed service {path}")


# ---------------------------------------------------------------- actions
def smoke_test(exe: Path, run_args: list[str], port: int, env: dict[str, str]) -> None:
    say(f"  starting APIEdge on port {port} for a health check ...")
    proc = subprocess.Popen([str(exe), "run", "--no-migrate", *run_args], env=env)  # nosec B603
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                fail(f"APIEdge exited early with code {proc.returncode}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:  # nosec B310
                    body = r.read().decode()
                if r.status == 200 and '"ok"' in body:
                    say(f"  GET /healthz -> {r.status} {body}")
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as c:  # nosec B310
                        say(f"  GET /        -> {c.status} (web console)")
                    return
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass
            time.sleep(1)
        fail("APIEdge did not become healthy within 60 seconds")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def uninstall(venv_dir: Path, data_dir: Path, args: argparse.Namespace) -> int:
    say(f"Uninstalling {APP}")
    unregister_service()
    remove_shortcuts()
    if venv_dir.exists():
        shutil.rmtree(venv_dir)
        say(f"  removed {venv_dir}")
    close_log()
    if args.purge_data and data_dir.exists():
        if args.yes or ask_yes(
            f"Delete ALL data (database) in {data_dir}?", default=False, assume_yes=args.yes
        ):
            shutil.rmtree(data_dir)
            say(f"  removed {data_dir}")
    elif data_dir.exists():
        say(f"  kept data in {data_dir} (use --purge-data to delete it)")
    say("\nAPIEdge has been uninstalled.")
    return 0


def install(venv_dir: Path, data_dir: Path, args: argparse.Namespace) -> int:
    total = 8
    log_path = open_log(data_dir)
    say(f"  install log: {log_path}")
    step(1, total, "Checking Python")
    check_python()

    step(2, total, f"Preparing virtual environment: {venv_dir}")
    if venv_dir.exists() and not venv_is_healthy(venv_dir):
        say("  existing environment is broken or uses another Python - recreating it")
        shutil.rmtree(venv_dir)
    if not venv_dir.exists():
        venv.EnvBuilder(with_pip=True, upgrade_deps=False).create(venv_dir)
        say("  created")
    else:
        say("  reusing existing environment (upgrade/repair)")
    py = str(venv_python(venv_dir))
    pip = [
        py,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--require-hashes",
    ]
    net: list[str] = []
    if args.proxy:
        net += ["--proxy", args.proxy]
    if args.index_url:
        net += ["--index-url", args.index_url]
    pip += net

    step(3, total, "Installing hash-locked dependencies from PyPI")
    run([*pip, "-r", str(REQ / "build.lock")])
    locks = ["-r", str(REQ / "runtime.lock")]
    if args.dev:
        locks += ["-r", str(REQ / "dev.lock")]
    run([*pip, *locks])

    step(4, total, "Installing APIEdge from this checkout")
    target = ["-e", str(ROOT)] if args.dev else [str(ROOT)]
    run(
        [
            py,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
            "--no-build-isolation",
            "--force-reinstall",
            *net,
            *target,
        ]
    )

    exe = venv_apiedge(venv_dir)
    env = dict(os.environ, APIEDGE_DATA_DIR=str(data_dir))
    run_args = ["--data-dir", str(data_dir)]

    step(5, total, f"Initialising data directory and database: {data_dir}")
    run([str(exe), "init", *run_args], env=env)

    step(6, total, f"Ensuring the first SuperAdmin '{args.admin_user}' exists")
    admin = [str(exe), "create-admin", "--username", args.admin_user, "--if-missing", *run_args]
    interactive = sys.stdin.isatty() and not args.yes
    # Never logged: the output may contain the generated password.
    run(admin if interactive else [*admin, "--generate-password"], env=env, log_output=False)

    step(7, total, "Shortcuts and service")
    port_args = ["--port", str(args.port)] if args.port else []
    if args.shortcut or (
        args.shortcut is None
        and ask_yes("Create desktop / start-menu shortcuts?", default=False, assume_yes=args.yes)
    ):
        create_shortcuts(venv_dir, [*run_args, *port_args])
    else:
        say("  shortcuts: skipped")
    service_running = False
    if args.service or (
        args.service is None
        and ask_yes(
            "Start APIEdge automatically when you log in?", default=False, assume_yes=args.yes
        )
    ):
        service_running = register_service(venv_dir, data_dir, [*run_args, *port_args])
    else:
        say("  service: skipped")

    port = args.port or 8080
    step(8, total, "Starting APIEdge")
    if service_running and not args.smoke_test:
        url = f"http://localhost:{port}/"
        say(f"  running as a background service: {url}")
        if not args.no_start:
            webbrowser.open(url)
    elif args.smoke_test:
        smoke_test(exe, [*run_args, "--port", str(port)], port, env)
        say("\nSmoke test passed.")
    elif args.no_start:
        hint = subprocess.list2cmdline([str(exe), "run", "--open", *run_args, *port_args])
        say(f"  skipped. Start it later with:\n    {hint}")
    else:
        say(f"  console: http://localhost:{port}/   (press Ctrl+C to stop)")
        return subprocess.run(
            [
                str(exe),
                "run",
                "--open",
                "--no-migrate",
                *run_args,  # nosec B603
                "--port",
                str(port),
            ],
            env=env,
            check=False,
        ).returncode

    say(f"\n{APP} is installed. Re-run this installer at any time to upgrade or repair it.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="install",
        description="APIEdge one-click installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "--yes",
        "-y",
        "--unattended",
        action="store_true",
        help="non-interactive: accept defaults, generate the admin password",
    )
    ap.add_argument(
        "--local",
        action="store_true",
        help="put the virtual environment in ./.venv of this checkout",
    )
    ap.add_argument("--venv-dir", type=Path, help="explicit virtual environment directory")
    ap.add_argument("--data-dir", type=Path, help="APIEdge data directory (database, config)")
    ap.add_argument(
        "--dev",
        action="store_true",
        help="also install development tools and install APIEdge in editable mode",
    )
    ap.add_argument("--admin-user", default="admin", help="username of the first SuperAdmin")
    ap.add_argument("--port", type=int, help="console/gateway port (default 8080)")
    sc = ap.add_mutually_exclusive_group()
    sc.add_argument(
        "--shortcut",
        dest="shortcut",
        action="store_true",
        default=None,
        help="create desktop / start-menu shortcuts",
    )
    sc.add_argument("--no-shortcut", dest="shortcut", action="store_false")
    sv = ap.add_mutually_exclusive_group()
    sv.add_argument(
        "--service",
        dest="service",
        action="store_true",
        default=None,
        help="start APIEdge at logon (systemd user unit / launchd agent / Startup folder)",
    )
    sv.add_argument("--no-service", dest="service", action="store_false")
    ap.add_argument("--proxy", help="HTTP(S) proxy for downloads, e.g. http://user:pass@host:3128")
    ap.add_argument("--index-url", help="PyPI mirror (hashes are still enforced)")
    ap.add_argument("--no-start", action="store_true", help="do not start APIEdge at the end")
    ap.add_argument(
        "--smoke-test",
        action="store_true",
        help="start APIEdge, check /healthz and the console, then stop (CI)",
    )
    ap.add_argument(
        "--uninstall",
        action="store_true",
        help="remove the environment and shortcuts (data is kept)",
    )
    ap.add_argument(
        "--purge-data", action="store_true", help="with --uninstall: also delete the data directory"
    )
    args = ap.parse_args(argv)

    data_dir = (args.data_dir or default_data_dir()).expanduser().resolve()
    if args.venv_dir:
        venv_dir = args.venv_dir.expanduser().resolve()
    elif args.local:
        venv_dir = ROOT / ".venv"
    else:
        venv_dir = data_dir / "venv"

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    say(f"{APP} installer  (source: {ROOT})")
    try:
        if args.uninstall:
            return uninstall(venv_dir, data_dir, args)
        return install(venv_dir, data_dir, args)
    finally:
        close_log()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say("\ninterrupted")
        sys.exit(130)
