#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-$HOME/unifi-helper}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

if [[ -z "$SUDO" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: sudo is not installed and script is not running as root." >&2
  exit 2
fi

if [[ ! -d "$APP_DIR" ]]; then
  echo "ERROR: app directory not found: $APP_DIR" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
$SUDO apt update
$SUDO apt install -y python3 python3-venv python3-pip openssl zip

cd "$APP_DIR"

if [[ ! -d ".venv" ]]; then
  "$PYTHON_BIN" -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Bootstrap complete."
echo "Run audits with:"
echo "  cd $APP_DIR && source .venv/bin/activate && python -m unifi_audit.cli /path/to/backup.unf --profile cis-nist"
