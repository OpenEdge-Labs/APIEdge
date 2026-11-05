# Installation Guide

APIEdge runs on **Windows, macOS and Linux** (x86_64 and arm64). The only prerequisite is
**Python 3.11, 3.12 or 3.13**. The installer downloads the dependencies from PyPI; every file is checked
against the sha256 hashes in `requirements/*.lock`. Node.js is **not** needed: the web console is
prebuilt and included.

Other ways to run APIEdge: [pip (wheel)](#9-pip-wheel), [Docker and Docker Compose](#10-docker-and-docker-compose)
and [Kubernetes (Helm)](#11-kubernetes-helm). How to check a download is in
[Verifying release artifacts](#12-verifying-release-artifacts).

## 1. Get APIEdge

Either download the installer bundle for your OS from a release and unzip it:

| OS | Bundle | Contains |
|---|---|---|
| Windows | `apiedge-<version>-installer-windows.zip` | `install.bat` |
| macOS | `apiedge-<version>-installer-macos.zip` | `install.command` (and `install.sh` for a terminal) |
| Linux | `apiedge-<version>-installer-linux.zip` | `install.sh` |

A bundle holds APIEdge's own source, the prebuilt console and the hash locks, never third-party
packages; the installer still downloads those from PyPI. Unzip it with your file manager or
`unzip` (both keep the launchers executable on macOS and Linux).

or clone the repository:

```
git clone https://github.com/OpenEdge-Labs/APIEdge.git
```

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
admin user and data untouched. Read the [upgrade notes](upgrading.md) first and back up the data
directory.

## 5. Start APIEdge later

Use the shortcut, or run `<data dir>/venv/Scripts/apiedge.exe run --open` (Windows) or
`<data dir>/venv/bin/apiedge run --open` (macOS/Linux).

## 6. Corporate proxies and PyPI mirrors

Use `--proxy` and `--index-url`, or the standard pip variables (`HTTPS_PROXY`, `PIP_INDEX_URL`,
`PIP_CERT`). Hash checking still applies, so a mirror must serve the original files.

## 7. Uninstall

Run the installer with `--uninstall`. This removes the virtual environment, shortcuts and the logon
service, and keeps your data. Add `--purge-data` to delete the database and log too.

## 8. Developers

```
python scripts/install.py --local --dev --no-start     # .venv with ruff, mypy, bandit, pytest, pip-audit
.venv/bin/pytest            # Windows: .venv\Scripts\pytest
cd console && npm ci && npm run build                  # only when changing the console (Node.js 20+)
```

Maintainers change dependencies by editing `requirements/*.in` and running
`python scripts/update-locks.py`, then `python scripts/check-licenses.py --write`, and committing the
`.in`, `.lock` and `THIRD_PARTY_LICENSES.md` files together.

## 9. pip (wheel)

The wheel `apiedge-<version>-py3-none-any.whl` contains APIEdge and the prebuilt console. Install
the dependencies from the hash lock first, so you get exactly the tested versions:

```
python -m venv apiedge-venv
apiedge-venv/bin/pip install --require-hashes -r requirements/runtime.lock    # Windows: apiedge-venv\Scripts\pip
apiedge-venv/bin/pip install --no-deps apiedge-<version>-py3-none-any.whl
apiedge-venv/bin/apiedge init
apiedge-venv/bin/apiedge create-admin
apiedge-venv/bin/apiedge run --open
```

`requirements/runtime.lock` is in every installer bundle and in the repository. A plain
`pip install apiedge-<version>-py3-none-any.whl` also works and resolves the version ranges in
`pyproject.toml`, without hash checking. APIEdge is not published on PyPI yet.

## 10. Docker and Docker Compose

The image (`packaging/docker/Dockerfile`) is built for linux/amd64 and linux/arm64. It runs as the
unprivileged user 10001, keeps its data (SQLite database, secrets key, captures) in the volume
`/var/lib/apiedge`, listens on 8080 (console and admin API) and 8081 (gateway), and has a health
check on `/healthz`. No image is published to a registry yet, so build it from the source tree:

```
docker build -f packaging/docker/Dockerfile -t apiedge:local .
docker run -d --name apiedge -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081   -v apiedge-data:/var/lib/apiedge apiedge:local
docker logs apiedge        # the generated first admin password is shown here ONCE
```

On first start the container applies migrations, creates the secrets key in the volume and the
first SuperAdmin. Set `APIEDGE_ADMIN_USER` to change its name, and `APIEDGE_ADMIN_PASSWORD_FILE`
to read its password from a mounted secret instead of generating one. The password must be changed
at the first sign-in. Any other `APIEDGE_*` setting from `.env.example` can be passed with `-e`.
`docker run apiedge:local version` (or `migrate`) runs a single `apiedge` command.

**Docker Compose** (`docker-compose.yml`) runs APIEdge with PostgreSQL 17 and Valkey (a
BSD-licensed, Redis-compatible server used for configuration events and shared rate limits):

```
export POSTGRES_PASSWORD='choose-a-strong-password'     # or put it in a .env file next to the compose file
docker compose up -d --build
docker compose logs apiedge                              # first admin password, shown once
```

Ports are published on `127.0.0.1` only (`APIEDGE_CONSOLE_PORT`, `APIEDGE_GATEWAY_PUBLISH_PORT`
change them); put a TLS reverse proxy in front to expose APIEdge. The APIEdge container has a
read-only root filesystem and no Linux capabilities. Back up both volumes: `postgres-data` (the
database) and `apiedge-data` (the secrets key, without which encrypted secrets cannot be read).
`docker compose down` stops the stack and keeps the data; `down -v` deletes it.

The compose file builds the image with `--build-arg APIEDGE_WITH_POSTGRES=1`, which adds the
PostgreSQL driver (psycopg 3, hash-pinned in `packaging/docker/postgres-driver.txt`). The driver is
not part of the default image or of the one-click installer yet: adding it to the runtime lock is
proposal VP-002, which needs a license review (psycopg is LGPL-3.0). The default image uses SQLite.

## 11. Kubernetes (Helm)

The chart is in `packaging/helm/apiedge` (and `apiedge-<chart version>.tgz` in a release). Push an
image you built (section 10) to your registry, then:

```
helm install apiedge packaging/helm/apiedge -n apiedge --create-namespace   --set image.repository=registry.example.com/apiedge --set image.tag=<version>
kubectl -n apiedge logs deploy/apiedge | grep -A1 "Generated password"
kubectl -n apiedge port-forward svc/apiedge 8080:8080
```

Useful values (see `values.yaml`):

| Value | Meaning |
|---|---|
| `admin.existingSecret` | Secret with the first admin password (key `password`) instead of a generated one |
| `secretKey.existingSecret` | Secret with the secrets master key (key `secret-key`); recommended |
| `database.existingSecret` / `redis.existingSecret` | Secrets with `APIEDGE_DATABASE_URL` / `APIEDGE_REDIS_URL` (keys `database-url`, `redis-url`). PostgreSQL needs an image built with `APIEDGE_WITH_POSTGRES=1` |
| `persistence.*` | the data volume (1 GiB ReadWriteOnce by default; kept on `helm uninstall`) |
| `ingress.*` | Ingress hosts for the console (`consoleHost`) and the gateway (`gatewayHost`), with TLS |
| `env` | extra non-secret `APIEDGE_*` settings |

The chart runs one replica (`Recreate` strategy) with a non-root, read-only root filesystem, no
service-account token and the `RuntimeDefault` seccomp profile. Multi-replica high availability
comes with clustering (T-026).

## 12. Verifying release artifacts

Each release contains `SHA256SUMS`, and `SHA256SUMS.asc` when it is signed. Check a download
before you use it:

```
sha256sum -c --ignore-missing SHA256SUMS                     # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS                 # macOS
Get-FileHash apiedge-<version>-installer-windows.zip         # Windows: compare with SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS                       # signature, with the OpenEdge Labs release key
```

`apiedge-<version>.cdx.json` is a CycloneDX 1.5 software bill of materials listing every Python
package of the runtime lock and the npm packages bundled into the console, with versions, package
URLs and licenses. Feed it to your vulnerability scanner (for example Dependency-Track or grype).

`apiedge-<version>-docs.zip` is this documentation as a static site: unzip it and open
`index.html` in a browser (search needs a web server, for example
`python -m http.server -d <unzipped folder>`).
