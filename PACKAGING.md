# Packaging & Distribution Plan

How the integration reaches each platform, from most- to least-automated.
The web app itself is identical everywhere; packaging only changes how the
server process is installed, started, and kept running.

| Platform | Recommended install | Status |
| --- | --- | --- |
| Docker (any) | `docker compose up -d` | Dockerfile + compose in repo; image built by CI |
| macOS (desktop) | `SquareProtect.dmg` menu-bar app | Build script in repo (`scripts/macos/build_dmg.sh`); needs Apple signing before public release |
| macOS (headless) | `scripts/install-service.sh` (launchd) | In repo |
| Linux / Raspberry Pi | `scripts/install-service.sh` (systemd) or Docker | In repo |
| TrueNAS SCALE | Docker/Apps (compose YAML below) | Documented |
| Homebridge / HOOBS hosts | Docker or systemd on the same Pi | Documented |
| Windows | `scripts/windows/install-service.ps1` (Task Scheduler) | In repo; MSI installer is future work |

## 1. Docker (the universal answer)

`Dockerfile` builds a slim image; `docker-compose.yml` runs it with a
persistent `./data` volume:

```bash
docker compose up -d       # dashboard on http://<host>:8000
```

CI (`.github/workflows/docker.yml`) builds the image on every push to main
so releases can publish it to GHCR (`ghcr.io/jimboha/square-unifi-protect`)
with one added permissions line when desired.

**TrueNAS SCALE:** Apps → Custom App → use the compose YAML, mounting a
dataset at `/data`. **Homebridge hosts:** the same compose file runs
alongside Homebridge on the Pi; or use the systemd installer below.

## 2. macOS menu-bar app (.dmg)

`scripts/macos/menubar_app.py` wraps the server in a native menu-bar app
(status icon, Open Dashboard, Start at Login hint, Quit). Build:

```bash
scripts/macos/build_dmg.sh          # → dist/SquareProtect.dmg
```

The script bundles with PyInstaller (`LSUIElement` set so there is no Dock
icon), verifies the app boots and serves the dashboard, then wraps it in a
drag-to-Applications dmg. **Release checklist:** codesign with a Developer ID
certificate, notarize (`xcrun notarytool submit`), staple, then attach the
dmg to a GitHub release. Unsigned builds run via right-click → Open.

## 3. Install as a service (auto-start at boot)

`scripts/install-service.sh` detects the OS:

- **macOS:** installs a `launchd` LaunchAgent
  (`~/Library/LaunchAgents/com.squareprotect.app.plist`), starts at login.
- **Linux (Debian/Ubuntu/Raspberry Pi OS):** installs a `systemd` unit
  (`/etc/systemd/system/square-protect.service`), starts at boot. The service
  listens on the network with the app's built-in TLS; open
  `https://<host>:8000`, accept the self-signed certificate warning, and run
  `sudo journalctl -u square-protect -b --no-pager` to find the generated
  one-time setup secret. No plaintext secret is stored in the unit.

Both use the repo checkout + its venv; `--uninstall` reverses everything.

## 4. Windows

`scripts/windows/install-service.ps1` creates the venv and registers a
Task Scheduler job that starts the server at logon (no third-party service
wrapper needed). When secure first-run setup is available, the installer
prints its one-time secret and hands it to the hidden task through a
DPAPI-protected, current-user-only file. The runner removes that encrypted
handoff automatically after setup succeeds; the task definition never stores
the plaintext secret. Docker Desktop users should prefer the compose file.
Future work: a signed MSI built with WiX + a pythonw-based tray icon,
mirroring the macOS menu-bar app.

## 5. Release automation (future)

One GitHub Actions release workflow producing: the Docker image (GHCR),
the signed/notarized dmg (needs Apple credentials as repo secrets), and a
source tarball; versioned by git tag.
