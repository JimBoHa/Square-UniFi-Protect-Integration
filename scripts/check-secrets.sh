#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks is required: https://github.com/gitleaks/gitleaks" >&2
  exit 2
fi

common_args=(
  --config=.gitleaks.toml
  --gitleaks-ignore-path=.gitleaksignore
  --no-banner
  --no-color
  --redact=100
)

echo "Scanning all reachable Git history..."
gitleaks git "${common_args[@]}" --log-opts="--all"

echo "Scanning current tracked and non-ignored files..."
git ls-files -co --exclude-standard -z |
  while IFS= read -r -d '' path; do
    if [[ -f "$path" ]]; then
      printf '\n--- FILE: %s ---\n' "$path"
      command cat -- "$path"
    fi
  done |
  gitleaks stdin "${common_args[@]}" --log-level=error

echo "No secrets detected."
