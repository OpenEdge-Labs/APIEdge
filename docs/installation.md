# Installation Guide

APIEdge runs on **Windows, macOS and Linux** (x86_64 and arm64). The only prerequisite is
**Python 3.10, 3.11 or 3.12**. The installer downloads the dependencies from PyPI; every file is checked
against the sha256 hashes in `requirements/*.lock`. Node.js is **not** needed: the web console is
prebuilt and included.

## 1. Get APIEdge

```
git clone https://github.com/alinganpatra20004/APIEdge.git
```
(or download and unzip the source archive from GitHub)

## 2. Run the one-click installer

| OS | Double-click | or from a terminal |
|---|---|---|
| Windows | `install.bat` | `install.bat` |
| macOS | `install.command` (first time: right-click → Open, to pass Gatekeeper) | `./install.command` |
| Linux | `install.sh` (if your file manager runs scripts) | `./install.sh` |

The installer:

1. checks Python (and tells you where to get it if it is missing or too old/new),
2. creates a virtual environment in the APIEdge data directory,
3. installs the hash-locked dependencies from PyPI,
4. installs APIEdge from the checkout,
5. creates the database and applies migrations,
6. creates the first SuperAdmin `admin`: you type a password, or leave it empty and a strong one is
   **generated and shown once**. You must change it at first login,
7. optionally creates desktop / start-menu shortcuts and registers APIEdge to start at logon,
8. starts APIEdge and opens the console at <http://localhost:8080/>. Press Ctrl+C to stop it.

Where things go:

| OS | Data directory (database, venv) |
|---|---|
| Windows | `%LOCALAPPDATA%\APIEdge\APIEdge` |
| macOS | `~/Library/Application Support/APIEdge` |
| Linux | `~/.local/share/APIEdge` (or `$XDG_DATA_HOME/APIEdge`) |

## 3. Options

All wrappers pass their arguments to `scripts/install.py`:

| Option | Meaning |
|---|---|
| `--unattended` (alias `--yes`) | no questions: accept defaults, generate the admin password, no shortcuts or service |
| `--port N` | console/gateway port (default 8080) |
| `--data-dir DIR` | use another data directory |
| `--venv-dir DIR` / `--local` | put the virtual environment elsewhere / in `./.venv` |
| `--admin-user NAME` | username of the first SuperAdmin (default `admin`) |
| `--shortcut` / `--no-shortcut` | create shortcuts without asking / never |
| `--service` / `--no-service` | start APIEdge automatically at logon (Linux: systemd user unit, macOS: launchd agent, Windows: Startup folder entry). No admin rights needed |
| `--proxy URL` | HTTP(S) proxy for the downloads (credentials are redacted in the log) |
| `--index-url URL` | PyPI mirror; hashes are still enforced, so the mirror must serve the original files |
| `--no-start` | install only |
| `--smoke-test` | start, check `/healthz` and the console, stop (used by CI) |
| `--dev` | developers: also install the dev tools and install APIEdge in editable mode |
| `--uninstall [--purge-data]` | remove the venv and shortcuts; `--purge-data` also deletes the database |

Every run appends to `install.log` in the data directory. Command output is logged, except the
admin-creation step, so a generated password is never written to disk.

## 4. Upgrade or repair

Pull the new version (`git pull`) and run the installer again. It reuses the environment (or recreates
it if it is broken), reinstalls the locked versions, applies new migrations, and leaves your existing
admin user and data untouched.

## 5. Start APIEdge later

Use the shortcut, or run `<data dir>/venv/Scripts/apiedge.exe run --open` (Windows) or
`<data dir>/venv/bin/apiedge run --open` (macOS/Linux).

## 6. Corporate proxies and PyPI mirrors

Use `--proxy` and `--index-url`, or the standard pip variables (`HTTPS_PROXY`, `PIP_INDEX_URL`,
`PIP_CERT`). Hash checking still applies, so a mirror must serve the original files.

## 6a. Uninstall

Run the installer with `--uninstall`. This removes the virtual environment, shortcuts and the logon
service, and keeps your data. Add `--purge-data` to delete the database and log too.

## 7. Developers

```
python scripts/install.py --local --dev --no-start     # .venv with ruff, mypy, bandit, pytest, pip-audit
.venv/bin/pytest            # Windows: .venv\Scripts\pytest
cd console && npm ci && npm run build                  # only when changing the console (Node.js 20+)
```

Maintainers change dependencies by editing `requirements/*.in` and running
`python scripts/update-locks.py`, then `python scripts/check-licenses.py --write`, and committing the
`.in`, `.lock` and `THIRD_PARTY_LICENSES.md` files together.
