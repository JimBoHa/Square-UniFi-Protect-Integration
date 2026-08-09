#!/bin/bash
# Install the integration as a background service that starts at boot/login.
#   macOS -> launchd LaunchAgent      Linux -> systemd unit
# Usage: scripts/install-service.sh [--uninstall]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNINSTALL="${1:-}"

if [ "$UNINSTALL" != "--uninstall" ]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust/Cargo is required. Install it from https://rustup.rs and run this installer again." >&2
    exit 1
  fi
  echo "Building the Rust service..."
  cargo build --manifest-path "$REPO/Cargo.toml" --locked --release
fi

BINARY="$REPO/target/release/square-unifi-protect"

case "$(uname -s)" in
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/com.squareprotect.app.plist"
    if [ "$UNINSTALL" = "--uninstall" ]; then
      launchctl unload "$PLIST" 2>/dev/null || true
      rm -f "$PLIST"
      echo "Uninstalled launchd agent."
      exit 0
    fi
    mkdir -p "$HOME/Library/LaunchAgents"
    mkdir -p "$REPO/data"
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.squareprotect.app</string>
  <key>ProgramArguments</key><array>
    <string>$BINARY</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO</string>
  <key>EnvironmentVariables</key><dict>
    <key>SPI_DATA_DIR</key><string>$REPO/data</string>
    <key>SPI_HOST</key><string>0.0.0.0</string>
    <key>SPI_TLS</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$REPO/data/service.log</string>
  <key>StandardErrorPath</key><string>$REPO/data/service.log</string>
</dict></plist>
PLIST_EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "Installed. The app starts at login; dashboard: https://<this-host>:8000"
    echo "The certificate refreshes when this computer's LAN IP changes."
    echo "Accept the self-signed certificate warning in your browser."
    ;;
  Linux)
    UNIT=/etc/systemd/system/square-protect.service
    if [ "$UNINSTALL" = "--uninstall" ]; then
      sudo systemctl disable --now square-protect 2>/dev/null || true
      sudo rm -f "$UNIT"
      sudo systemctl daemon-reload
      echo "Uninstalled systemd unit."
      exit 0
    fi
    sudo tee "$UNIT" >/dev/null <<UNIT_EOF
[Unit]
Description=Square x UniFi Protect integration
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
WorkingDirectory=$REPO
Environment=SPI_DATA_DIR=$REPO/data
Environment=SPI_HOST=0.0.0.0
Environment=SPI_TLS=1
ExecStart=$BINARY
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT_EOF
    sudo systemctl daemon-reload
    sudo systemctl enable square-protect
    sudo systemctl restart square-protect
    echo "Installed. Dashboard: https://<this-host>:8000"
    echo "Accept the self-signed certificate warning in your browser."
    echo "For the one-time setup secret, run:"
    echo "  sudo journalctl -u square-protect -b --no-pager"
    ;;
  *)
    echo "Unsupported OS: $(uname -s). Use Docker or the Windows script."
    exit 1
    ;;
esac
