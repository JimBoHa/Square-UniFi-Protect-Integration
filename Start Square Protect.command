#!/bin/bash
# Double-clickable launcher for the Square × UniFi Protect integration.
# Creates the Python environment on first run, starts the server, and opens
# the dashboard in your browser. Close this window to stop the server.
set -e
cd "$(dirname "$0")"

invalid_port() {
  echo "SPI_PORT must be a whole number from 1 to 65535." >&2
  read -r -p "Press Return to close..." _ || true
  exit 1
}

PORT="${SPI_PORT-8000}"
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
PORT_START="$PORT"

if [ ! -x .venv/bin/python ]; then
  # python3 is only needed to create the environment; an already-provisioned
  # machine can launch without it.
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required but was not found."
    echo "Install the Apple Command Line Tools by running:  xcode-select --install"
    echo "or download Python from https://www.python.org/downloads/  then run this again."
    read -r -p "Press Return to close..." _
    exit 1
  fi
  echo "First run: setting up the Python environment (about a minute)..."
  python3 -m venv .venv
fi

.venv/bin/python scripts/ensure_dependencies.py "$PWD" "$PWD/.venv"

# Lets automated checks verify setup without starting a browser or server.
[ "${SPI_LAUNCHER_SETUP_ONLY:-0}" = "1" ] && exit 0

PORT_CAP=$((PORT + 20))
if [ "$PORT_CAP" -gt 65535 ]; then
  PORT_CAP=65535
fi
# If the preferred port is taken (another copy running, or another app),
# walk forward to the next free port instead of failing with a traceback.
while lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; do
  if [ "$PORT" -ge "$PORT_CAP" ]; then
    echo "Could not find a free port between $PORT_START and $PORT_CAP."
    read -r -p "Press Return to close..." _
    exit 1
  fi
  echo "Port $PORT is in use; trying $((PORT + 1))..."
  PORT=$((PORT + 1))
done

export SPI_DATA_DIR="${SPI_DATA_DIR:-$PWD/data}"

SCHEME="http"
[ "${SPI_TLS:-0}" = "1" ] && SCHEME="https"

echo
echo "Starting Square × UniFi Protect on $SCHEME://localhost:$PORT"
echo "Your settings and transaction data live in: $SPI_DATA_DIR"
echo "Keep this window open while using the app; close it (or press Ctrl+C) to stop."
echo

( sleep 2 && open "$SCHEME://localhost:$PORT" ) &
# python -m app honors SPI_TLS (self-signed HTTPS + Secure cookies).
export SPI_HOST="${SPI_HOST:-127.0.0.1}"
export SPI_PORT="$PORT"
exec .venv/bin/python -m app
