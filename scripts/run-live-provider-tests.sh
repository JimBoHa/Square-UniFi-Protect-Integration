#!/bin/bash
set -euo pipefail

prompt_value() {
  local variable_name="$1"
  local prompt="$2"
  local secret="${3:-0}"
  local value="${!variable_name-}"

  if [ -z "$value" ]; then
    if [ ! -t 0 ]; then
      echo "$variable_name is required. Run this script interactively so it can prompt without storing credentials." >&2
      exit 2
    fi
    if [ "$secret" = "1" ]; then
      read -r -s -p "$prompt: " value
      echo
    else
      read -r -p "$prompt: " value
    fi
  fi
  if [ -z "$value" ]; then
    echo "$variable_name cannot be empty." >&2
    exit 2
  fi
  export "$variable_name=$value"
}

prompt_value SPI_TEST_SQUARE_ACCESS_TOKEN "Square Sandbox access token" 1
prompt_value SPI_TEST_PROTECT_HOST "UniFi Protect host or IP"
prompt_value SPI_TEST_PROTECT_USERNAME "UniFi Protect local username"
prompt_value SPI_TEST_PROTECT_PASSWORD "UniFi Protect local password" 1

echo "Running opt-in live tests. This creates 10 completed Square Sandbox payments."
cargo test --locked --test live_provider_flows -- --ignored --test-threads=1 --nocapture
