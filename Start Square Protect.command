#!/bin/bash
# Double-clickable launcher for the Square × UniFi Protect integration.
# Creates the Python environment on first run, starts the server, and opens
# the dashboard in your browser. Close this window to stop the server.
set -e
cd "$(dirname "$0")"

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

if ! .venv/bin/python -c 'import cryptography, fastapi, httpx, uvicorn' >/dev/null 2>&1; then
  echo "Installing or repairing Python dependencies (about a minute)..."
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -e .
fi

# Lets automated checks verify setup without starting a browser or server.
[ "${SPI_LAUNCHER_SETUP_ONLY:-0}" = "1" ] && exit 0

PORT="${SPI_PORT:-8000}"
PORT_CAP=$((PORT + 20))
# If the preferred port is taken (another copy running, or another app),
# walk forward to the next free port instead of failing with a traceback.
while lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; do
  echo "Port $PORT is in use; trying $((PORT + 1))..."
  PORT=$((PORT + 1))
  if [ "$PORT" -gt "$PORT_CAP" ]; then
    echo "Could not find a free port between ${SPI_PORT:-8000} and $PORT_CAP."
    read -r -p "Press Return to close..." _
    exit 1
  fi
done

export SPI_DATA_DIR="${SPI_DATA_DIR:-$PWD/data}"

echo
echo "Starting Square × UniFi Protect on http://localhost:$PORT"
echo "Your settings and transaction data live in: $SPI_DATA_DIR"
echo "Keep this window open while using the app; close it (or press Ctrl+C) to stop."
echo

( sleep 2 && open "http://localhost:$PORT" ) &
exec .venv/bin/uvicorn app.main:app --factory --host 127.0.0.1 --port "$PORT"
