#!/bin/bash
# Double-clickable launcher for the Square × UniFi Protect integration.
# Builds the Rust binary on first run, starts the server, and opens
# the dashboard in your browser. Close this window to stop the server.
set -e
cd "$(dirname "$0")"

invalid_port() {
  echo "SPI_PORT must be a whole number from 1 to 65535." >&2
  read -r -p "Press Return to close..." _ || true
  exit 1
}

PORT="${SPI_PORT-3546}"
case "$PORT" in
  ""|*[!0-9]*) invalid_port ;;
esac
# Normalize leading zeroes before Bash arithmetic, where 0-prefixed values are
# otherwise interpreted as octal.
while [ "${PORT#0}" != "$PORT" ]; do
  PORT="${PORT#0}"
done
[ -n "$PORT" ] || PORT=0
if [ "${#PORT}" -gt 5 ] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  invalid_port
fi
if [ -n "${SPI_LAUNCHER_BINARY:-}" ]; then
  BINARY="$SPI_LAUNCHER_BINARY"
  if [ ! -x "$BINARY" ]; then
    echo "SPI_LAUNCHER_BINARY is not executable: $BINARY" >&2
    exit 1
  fi
else
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust/Cargo is required but was not found."
    echo "Install it from https://rustup.rs, then run this launcher again."
    read -r -p "Press Return to close..." _
    exit 1
  fi

  echo "Building the Rust server (the first build can take a few minutes)..."
  cargo build --locked --release
  BINARY="$PWD/target/release/square-unifi-protect"
fi

# Lets automated checks verify setup without starting a browser or server.
[ "${SPI_LAUNCHER_SETUP_ONLY:-0}" = "1" ] && exit 0

# A stable port keeps Square and Protect webhook URLs valid across restarts.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Square Protect requires fixed TCP port $PORT, but it is already in use." >&2
  echo "Stop the service using it or set SPI_PORT explicitly before starting." >&2
  read -r -p "Press Return to close..." _
  exit 1
fi

export SPI_DATA_DIR="${SPI_DATA_DIR:-$PWD/data}"

SCHEME="http"
[ "${SPI_TLS:-0}" = "1" ] && SCHEME="https"

echo
echo "Starting Square × UniFi Protect on $SCHEME://localhost:$PORT"
echo "Your settings and transaction data live in: $SPI_DATA_DIR"
echo "Keep this window open while using the app; close it (or press Ctrl+C) to stop."
echo

( sleep 2 && open "$SCHEME://localhost:$PORT" ) &
export SPI_HOST="${SPI_HOST:-127.0.0.1}"
export SPI_PORT="$PORT"
exec "$BINARY"
