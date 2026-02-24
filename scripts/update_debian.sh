#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-$HOME/unifi-helper}"

if [[ ! -d "$APP_DIR" ]]; then
  echo "ERROR: app directory not found: $APP_DIR" >&2
  exit 2
fi

cd "$APP_DIR"

if [[ ! -d ".venv" ]]; then
  echo "Virtual environment missing. Bootstrapping first..."
  if [[ -x "./bootstrap_debian.sh" ]]; then
    ./bootstrap_debian.sh "$APP_DIR"
    exit 0
  fi
  echo "ERROR: .venv and bootstrap_debian.sh are both missing." >&2
  exit 2
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python -m compileall -q unifi_audit

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files | grep -q '^unifi-helper-web\.service'; then
    if command -v sudo >/dev/null 2>&1; then
      sudo systemctl restart unifi-helper-web.service || true
    elif [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      systemctl restart unifi-helper-web.service || true
    fi
  fi
fi

echo "Update complete."
echo "Run audits with:"
echo "  cd $APP_DIR && source .venv/bin/activate && python -m unifi_audit.cli /path/to/backup.unf --profile cis-nist"
