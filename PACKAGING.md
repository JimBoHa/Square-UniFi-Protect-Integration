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

`Dockerfile` compiles the Rust backend in a pinned builder and copies only the
native binary, browser assets, and CA roots into a slim runtime image;
`docker-compose.yml` runs it with a
persistent `./data` volume:

```bash
docker compose up -d
docker compose logs square-protect
```

Open `https://<host>:3546`, accept the one-time self-signed certificate
warning, and enter the generated setup secret printed in the startup output.
The container enables the app's built-in TLS by default because its wildcard
bind is reachable from other devices. It deliberately does not retain a
plaintext setup secret in Compose or container metadata. The generated secret
is invalidated as soon as first-run setup succeeds; restarting before setup
rotates it.

CI (`.github/workflows/docker.yml`) builds the image on every push to main
so releases can publish it to GHCR (`ghcr.io/jimboha/square-unifi-protect`)
with one added permissions line when desired.

**TrueNAS SCALE:** Apps → Custom App → use the compose YAML, mounting a
dataset at `/data`. **Homebridge hosts:** the same compose file runs
alongside Homebridge on the Pi; or use the systemd installer below.

## 2. macOS menu-bar app (.dmg)

The `square-protect-menubar` Rust binary wraps the Rust server in a native
menu-bar app (status icon, Open Dashboard, Open Data Folder, one-time setup
secret, and Quit). Build:

```bash
scripts/macos/build_dmg.sh          # → dist/SquareProtect.dmg
```

The script compiles both locked Rust release binaries, assembles a native
`LSUIElement` app bundle without Python or PyInstaller, validates its embedded
server and browser assets, and wraps the code-signed app in a
drag-to-Applications dmg. Local and pull-request builds use an ad-hoc code
signature. For a public release, set `MACOS_SIGNING_IDENTITY` to a Developer ID
Application identity, add a secure timestamp, sign the completed disk image,
submit it with `xcrun notarytool`, and staple the accepted ticket before
publishing it.

Developer ID signing and Apple notarization make the download acceptable to
macOS Gatekeeper; they do **not** create a TLS server certificate trusted by a
Protect console. The current motion webhook requires a reachable listener, and
an HTTPS webhook requires a per-installation hostname, private key, and trusted
certificate. The preferred product target instead connects outward to each
store's local Protect event WebSocket, avoiding app-side certificate and DNS
setup for motion. The current DMG wrapper starts on loopback, so neither LAN
mode is available from a Finder launch yet. See
[Protect event delivery and TLS trust](TLS.md) for the trust boundaries,
fallbacks, and implementation order.
Unsigned builds run via right-click → Open.

## 3. Install as a service (auto-start at boot)

`scripts/install-service.sh` detects the OS:

- **macOS:** installs a `launchd` LaunchAgent
  (`~/Library/LaunchAgents/com.squareprotect.app.plist`), starts at login and
  listens on all LAN interfaces with built-in TLS. Its generated certificate
  follows the computer's resolved LAN addresses after a DHCP change.
- **Linux (Debian/Ubuntu/Raspberry Pi OS):** installs a `systemd` unit
  (`/etc/systemd/system/square-protect.service`), starts at boot. The service
  listens on the network with the app's built-in TLS; open
  `https://<host>:3546`, accept the self-signed certificate warning, and run
  `sudo journalctl -u square-protect -b --no-pager` to find the generated
  one-time setup secret. No plaintext secret is stored in the unit.

Both compile the locked Rust release binary from the repo checkout;
`--uninstall` reverses the service registration. Re-running the installer after
an update rebuilds the binary before restarting the service.

All packaged deployments reserve TCP port `3546`. They fail clearly rather
than switching ports when it is occupied, because inbound Square and UniFi
Protect webhook URLs require a stable address. Set `SPI_PORT` only when the
deployment definition, firewall, bookmarks, and webhook URLs are changed
together.

## 4. Windows

`scripts/windows/install-service.ps1` compiles the locked Rust release and
registers a Task Scheduler job that starts it at logon (no third-party service
wrapper needed). On first run, the installer prints its one-time secret and
hands it to the hidden task through a
DPAPI-protected, current-user-only file. The runner removes that encrypted
handoff automatically after setup succeeds; the task definition never stores
the plaintext secret. Docker Desktop users should prefer the compose file.
Future work: a signed MSI built with WiX + a native tray icon,
mirroring the macOS menu-bar app.

## 5. Release automation (future)

One GitHub Actions release workflow producing: the Docker image (GHCR),
the signed/notarized dmg (needs Apple credentials as repo secrets), and a
source tarball; versioned by git tag. Signing credentials must be restricted to
the release environment and remain completely separate from per-installation
TLS keys and ACME/DNS credentials. The release and runtime acceptance criteria
are detailed in [TLS.md](TLS.md).
