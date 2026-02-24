#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-$HOME/unifi-helper}"
RUN_AS_USER="${2:-$(id -un)}"
BIND_HOST="${3:-0.0.0.0}"
BIND_PORT="${4:-8080}"
MAX_UPLOAD_MB="${5:-128}"
MEMORY_MAX="${6:-2G}"
MEMORY_HIGH="${7:-1500M}"
SERVICE_NAME="unifi-helper-web.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
TEMPLATE_PATH="$APP_DIR/unifi-helper-web.service"

if [[ ! -d "$APP_DIR" ]]; then
  echo "ERROR: app directory not found: $APP_DIR" >&2
  exit 2
fi

if [[ ! -f "$APP_DIR/.venv/bin/python" ]]; then
  echo "ERROR: Python virtualenv not found at $APP_DIR/.venv. Run bootstrap first." >&2
  exit 2
fi

if [[ ! -f "$TEMPLATE_PATH" ]]; then
  echo "ERROR: service template missing: $TEMPLATE_PATH" >&2
  exit 2
fi

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

if [[ -z "$SUDO" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: sudo is not installed and script is not running as root." >&2
  exit 2
fi

TMP_SERVICE="$(mktemp)"
cleanup() {
  rm -f "$TMP_SERVICE"
}
trap cleanup EXIT

sed \
  -e "s|__RUN_AS_USER__|$RUN_AS_USER|g" \
  -e "s|__APP_DIR__|$APP_DIR|g" \
  -e "s|__BIND_HOST__|$BIND_HOST|g" \
  -e "s|__BIND_PORT__|$BIND_PORT|g" \
  -e "s|__MAX_UPLOAD_MB__|$MAX_UPLOAD_MB|g" \
  -e "s|__MEMORY_MAX__|$MEMORY_MAX|g" \
  -e "s|__MEMORY_HIGH__|$MEMORY_HIGH|g" \
  "$TEMPLATE_PATH" >"$TMP_SERVICE"

$SUDO cp "$TMP_SERVICE" "$SERVICE_PATH"
$SUDO chmod 644 "$SERVICE_PATH"
$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME"
$SUDO systemctl restart "$SERVICE_NAME"

echo "Installed and started $SERVICE_NAME"
echo "Manage with:"
echo "  systemctl status $SERVICE_NAME"
echo "  systemctl restart $SERVICE_NAME"
echo "  systemctl stop $SERVICE_NAME"
