#!/usr/bin/env sh
set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/sipflow}"
SERVICE_USER="${SERVICE_USER:-sipflow}"
HOST="${SIPFLOW_HOST:-0.0.0.0}"
PORT="${SIPFLOW_PORT:-8080}"
AUTH_USER="${SIPFLOW_AUTH_USER:-admin}"
AUTH_PASSWORD="${SIPFLOW_AUTH_PASSWORD:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_SOURCE="${SIPFLOW_PYTHON:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo ./install.sh" >&2
  exit 1
fi

if [ -z "$PYTHON_SOURCE" ]; then
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        PYTHON_SOURCE="$candidate"
        break
      fi
    fi
  done
fi

if [ -z "$PYTHON_SOURCE" ]; then
  echo "Python 3.10 or newer is required. Set SIPFLOW_PYTHON=/path/to/python3.10 if needed." >&2
  exit 1
fi

if ! command -v setcap >/dev/null 2>&1; then
  echo "setcap is required. Install libcap2-bin or your distro equivalent." >&2
  exit 1
fi

if [ -z "$AUTH_PASSWORD" ]; then
  if command -v openssl >/dev/null 2>&1; then
    AUTH_PASSWORD="$(openssl rand -base64 24)"
  else
    AUTH_PASSWORD="$("$PYTHON_SOURCE" -c 'import secrets; print(secrets.token_urlsafe(24))')"
  fi
fi

mkdir -p "$INSTALL_DIR"
INSTALL_DIR_ABS="$(CDPATH= cd -- "$INSTALL_DIR" && pwd)"
if [ ! -d "$SCRIPT_DIR/sipflow" ]; then
  echo "Cannot find $SCRIPT_DIR/sipflow. Run this installer from a complete SIPFLOW release." >&2
  exit 1
fi

if [ "$SCRIPT_DIR" != "$INSTALL_DIR_ABS" ]; then
  mkdir -p "$INSTALL_DIR/sipflow"
  cp -R "$SCRIPT_DIR/sipflow/." "$INSTALL_DIR/sipflow/"
  if [ -f "$SCRIPT_DIR/README.md" ]; then
    cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
  fi
else
  echo "Installer is already running from $INSTALL_DIR_ABS; skipping source copy."
fi
"$PYTHON_SOURCE" -m venv --copies "$INSTALL_DIR/.venv"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

PYTHON_BIN="$INSTALL_DIR/.venv/bin/python"
setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" || {
  echo "Unable to grant capture capabilities to $PYTHON_BIN" >&2
  exit 1
}

cat >/etc/systemd/system/sipflow.service <<EOF
[Unit]
Description=SIPFLOW browser SIP capture service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=SIPFLOW_AUTH_USER=$AUTH_USER
Environment=SIPFLOW_AUTH_PASSWORD=$AUTH_PASSWORD
ExecStart=$PYTHON_BIN -m sipflow.server --host $HOST --port $PORT
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sipflow
systemctl restart sipflow

echo "SIPFLOW installed."
echo "Open http://SERVER_IP:$PORT"
echo "Username: $AUTH_USER"
echo "Password: $AUTH_PASSWORD"
echo "Status: systemctl status sipflow"
