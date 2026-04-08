#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

prompt() {
  local message="$1"
  local default_value="$2"
  local answer
  read -r -p "${message} [${default_value}]: " answer
  if [[ -z "${answer}" ]]; then
    echo "${default_value}"
  else
    echo "${answer}"
  fi
}

prompt_secret() {
  local message="$1"
  local answer
  read -r -s -p "${message}: " answer
  echo
  echo "${answer}"
}

is_valid_port() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 ))
}

random_string() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48
  fi
}

echo "== Proxy Admin Panel installer =="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DETECTED_REPO_URL=""
if [[ -d "${PROJECT_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
  DETECTED_REPO_URL="$(git -C "${PROJECT_ROOT}" config --get remote.origin.url || true)"
fi
DEFAULT_REPO_URL="${REPO_URL:-${DETECTED_REPO_URL:-https://github.com/sashagusq-gif/proxy-admin-panel.git}}"
REPO_URL_VALUE="$(prompt "GitHub repository URL" "${DEFAULT_REPO_URL}")"
BRANCH_VALUE="$(prompt "Git branch" "main")"
INSTALL_DIR="$(prompt "Install directory" "/opt/proxy-admin-panel")"

PANEL_PORT="$(prompt "Panel port" "8000")"
while ! is_valid_port "${PANEL_PORT}"; do
  PANEL_PORT="$(prompt "Invalid port. Panel port" "8000")"
done

HTTP_PROXY_PORT="$(prompt "HTTP proxy port" "13128")"
while ! is_valid_port "${HTTP_PROXY_PORT}"; do
  HTTP_PROXY_PORT="$(prompt "Invalid port. HTTP proxy port" "13128")"
done

SOCKS_PROXY_PORT="$(prompt "SOCKS5 proxy port" "11080")"
while ! is_valid_port "${SOCKS_PROXY_PORT}"; do
  SOCKS_PROXY_PORT="$(prompt "Invalid port. SOCKS5 proxy port" "11080")"
done

ADMIN_USERNAME="$(prompt "Admin username" "admin")"
ADMIN_PASSWORD="$(prompt_secret "Admin password (leave empty for random)")"
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  ADMIN_PASSWORD="$(random_string)"
fi

PANEL_DOMAIN="$(prompt "Panel domain (empty = no domain)" "")"
USE_SSL="no"
if [[ -n "${PANEL_DOMAIN}" ]]; then
  USE_SSL="$(prompt "Issue SSL certificate via Caddy? (yes/no)" "yes")"
fi

PROXY_PUBLIC_HOST_DEFAULT="auto"
if [[ -n "${PANEL_DOMAIN}" ]]; then
  PROXY_PUBLIC_HOST_DEFAULT="${PANEL_DOMAIN}"
fi
PROXY_PUBLIC_HOST="$(prompt "Public host for tg:// and HTTP links" "${PROXY_PUBLIC_HOST_DEFAULT}")"

PROXY_LOGDUMP_BYTES="$(prompt "Low-load logdump bytes" "65536")"
TRAFFIC_POLL_INTERVAL_SECONDS="$(prompt "Traffic poll interval seconds" "2.0")"

echo "Installing system dependencies..."
apt-get update -y
apt-get install -y ca-certificates curl git openssl

if ! command -v docker >/dev/null 2>&1; then
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
fi

systemctl enable --now docker

if ! docker compose version >/dev/null 2>&1; then
  echo "Installing docker compose plugin..."
  apt-get install -y docker-compose-plugin
fi

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  echo "Updating existing repository in ${INSTALL_DIR}..."
  git -C "${INSTALL_DIR}" fetch --all --prune
  git -C "${INSTALL_DIR}" checkout "${BRANCH_VALUE}"
  git -C "${INSTALL_DIR}" pull --ff-only
else
  echo "Cloning repository to ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 --branch "${BRANCH_VALUE}" "${REPO_URL_VALUE}" "${INSTALL_DIR}"
fi

PANEL_SECRET_KEY="$(random_string)"

cat >"${INSTALL_DIR}/.env" <<EOF
PANEL_PORT=${PANEL_PORT}
HTTP_PROXY_PORT=${HTTP_PROXY_PORT}
SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT}
PANEL_SECRET_KEY=${PANEL_SECRET_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
PROXY_PUBLIC_HOST=${PROXY_PUBLIC_HOST}
PROXY_LOGDUMP_BYTES=${PROXY_LOGDUMP_BYTES}
TRAFFIC_POLL_INTERVAL_SECONDS=${TRAFFIC_POLL_INTERVAL_SECONDS}
EOF

if [[ "${USE_SSL}" =~ ^([yY]|[yY][eE][sS])$ ]] && [[ -n "${PANEL_DOMAIN}" ]]; then
  mkdir -p "${INSTALL_DIR}/deploy"
  cat >"${INSTALL_DIR}/deploy/Caddyfile" <<EOF
${PANEL_DOMAIN} {
  encode gzip
  reverse_proxy backend:8000
}
EOF
  echo "Starting stack with SSL profile..."
  docker compose -f "${INSTALL_DIR}/docker-compose.yml" --env-file "${INSTALL_DIR}/.env" --profile ssl up -d --build
else
  echo "Starting stack without SSL profile..."
  docker compose -f "${INSTALL_DIR}/docker-compose.yml" --env-file "${INSTALL_DIR}/.env" up -d --build
fi

echo
echo "== Installed successfully =="
if [[ "${USE_SSL}" =~ ^([yY]|[yY][eE][sS])$ ]] && [[ -n "${PANEL_DOMAIN}" ]]; then
  echo "Panel URL: https://${PANEL_DOMAIN}"
else
  echo "Panel URL: http://<server-ip>:${PANEL_PORT}"
fi
echo "Admin username: ${ADMIN_USERNAME}"
echo "Admin password: ${ADMIN_PASSWORD}"
echo "HTTP proxy port: ${HTTP_PROXY_PORT}"
echo "SOCKS5 proxy port: ${SOCKS_PROXY_PORT}"
