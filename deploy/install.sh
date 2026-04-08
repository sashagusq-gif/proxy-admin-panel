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

prompt_yes_no() {
  local message="$1"
  local default_value="$2"
  local answer
  while true; do
    read -r -p "${message} [${default_value}]: " answer
    if [[ -z "${answer}" ]]; then
      answer="${default_value}"
    fi
    case "${answer}" in
      y|Y|yes|YES|Yes) echo "yes"; return 0 ;;
      n|N|no|NO|No) echo "no"; return 0 ;;
      *) echo "Please answer yes or no." ;;
    esac
  done
}

is_valid_port() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 ))
}

sanitize_domain() {
  local raw="$1"
  raw="${raw#http://}"
  raw="${raw#https://}"
  raw="${raw%%/*}"
  raw="${raw,,}"
  echo "${raw}"
}

is_safe_env_value() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9._@:\-]+$ ]]
}

random_string() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48
  fi
}

contains_newline() {
  local value="$1"
  [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]
}

quote_env_value() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value//\'/\'\"\'\"\'}"
  printf "'%s'" "${value}"
}

echo "== Proxy Admin Panel installer =="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DETECTED_REPO_URL=""
if [[ -d "${PROJECT_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
  DETECTED_REPO_URL="$(git -C "${PROJECT_ROOT}" config --get remote.origin.url || true)"
fi
DEFAULT_REPO_URL="${REPO_URL:-${DETECTED_REPO_URL:-https://github.com/your-org/proxy-admin-panel.git}}"
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
while ! is_safe_env_value "${ADMIN_USERNAME}"; do
  ADMIN_USERNAME="$(prompt "Username has unsupported chars. Admin username" "admin")"
done

ADMIN_PASSWORD="$(prompt_secret "Admin password (leave empty for random, allowed: A-Za-z0-9._@:-)")"
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  ADMIN_PASSWORD="$(random_string)"
fi
while contains_newline "${ADMIN_PASSWORD}"; do
  ADMIN_PASSWORD="$(prompt_secret "Password has newline chars, enter again")"
  if [[ -z "${ADMIN_PASSWORD}" ]]; then
    ADMIN_PASSWORD="$(random_string)"
  fi
done

PANEL_DOMAIN="$(prompt "Panel domain (empty = no domain)" "")"
PANEL_DOMAIN="$(sanitize_domain "${PANEL_DOMAIN}")"
USE_SSL="no"
if [[ -n "${PANEL_DOMAIN}" ]]; then
  USE_SSL="$(prompt_yes_no "Issue SSL certificate via Caddy? (yes/no)" "yes")"
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

{
  echo "PANEL_PORT=${PANEL_PORT}"
  echo "HTTP_PROXY_PORT=${HTTP_PROXY_PORT}"
  echo "SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT}"
  echo "PANEL_SECRET_KEY=$(quote_env_value "${PANEL_SECRET_KEY}")"
  echo "ADMIN_USERNAME=$(quote_env_value "${ADMIN_USERNAME}")"
  echo "ADMIN_PASSWORD=$(quote_env_value "${ADMIN_PASSWORD}")"
  echo "PROXY_PUBLIC_HOST=$(quote_env_value "${PROXY_PUBLIC_HOST}")"
  echo "PROXY_LOGDUMP_BYTES=${PROXY_LOGDUMP_BYTES}"
  echo "TRAFFIC_POLL_INTERVAL_SECONDS=${TRAFFIC_POLL_INTERVAL_SECONDS}"
} >"${INSTALL_DIR}/.env"

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
  sleep 3
  if ! docker compose -f "${INSTALL_DIR}/docker-compose.yml" ps caddy | grep -q "Up"; then
    echo "Caddy failed to start. Recent logs:"
    docker compose -f "${INSTALL_DIR}/docker-compose.yml" logs --tail=80 caddy || true
  fi
else
  echo "Starting stack without SSL profile..."
  docker compose -f "${INSTALL_DIR}/docker-compose.yml" --env-file "${INSTALL_DIR}/.env" up -d --build
fi

sleep 2
LOGIN_HTTP_CODE="$(curl -s -o /tmp/panel-login-check.txt -w "%{http_code}" -X POST "http://127.0.0.1:${PANEL_PORT}/api/auth/login" -H "Content-Type: application/json" -d "{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}" || true)"
if [[ "${LOGIN_HTTP_CODE}" != "200" ]]; then
  echo "WARNING: login self-check failed with HTTP ${LOGIN_HTTP_CODE}."
  echo "Response:"
  cat /tmp/panel-login-check.txt || true
else
  echo "Login self-check: OK"
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
echo
echo "Saved credentials/env file: ${INSTALL_DIR}/.env"
if [[ "${USE_SSL}" == "yes" ]]; then
  echo "If HTTPS is not available yet, make sure DNS A record for ${PANEL_DOMAIN} points to this server and ports 80/443 are open."
fi
