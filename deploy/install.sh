#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

prompt_secret() {
  local message="$1"
  local answer
  read -r -s -p "${message}: " answer
  echo
  echo "${answer}"
}

prompt_text() {
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

prompt_port() {
  local message="$1"
  local default_value="$2"
  local answer
  while true; do
    read -r -p "${message} [${default_value}]: " answer
    if [[ -z "${answer}" ]]; then
      answer="${default_value}"
    fi
    if is_valid_port "${answer}"; then
      echo "${answer}"
      return 0
    fi
    echo "Invalid port. Must be 1..65535"
  done
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

sanitize_domain() {
  local raw="$1"
  raw="${raw#http://}"
  raw="${raw#https://}"
  raw="${raw%%/*}"
  raw="${raw,,}"
  echo "${raw}"
}

echo "== Proxy Admin Panel installer =="

REPO_URL_VALUE="${REPO_URL:-https://github.com/sashagusq-gif/proxy-admin-panel.git}"
BRANCH_VALUE="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/proxy-admin-panel}"
ADMIN_USERNAME="admin"

PANEL_PORT="$(prompt_port "Panel port" "8000")"
HTTP_PROXY_PORT="$(prompt_port "HTTP proxy port" "13128")"
SOCKS_PROXY_PORT="$(prompt_port "SOCKS5 proxy port" "11080")"

ADMIN_PASSWORD="$(prompt_secret "Admin password (leave empty for random)")"
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  ADMIN_PASSWORD="$(random_string)"
fi

PANEL_DOMAIN_RAW="$(prompt_text "Panel domain for HTTPS (empty = no HTTPS)" "")"
PANEL_DOMAIN="$(sanitize_domain "${PANEL_DOMAIN_RAW}")"
USE_SSL="no"
if [[ -n "${PANEL_DOMAIN}" ]]; then
  USE_SSL="$(prompt_yes_no "Issue SSL certificate via Caddy? (yes/no)" "yes")"
fi

PROXY_PUBLIC_HOST="auto"
if [[ -n "${PANEL_DOMAIN}" ]]; then
  PROXY_PUBLIC_HOST="${PANEL_DOMAIN}"
fi
PROXY_LOGDUMP_BYTES="${PROXY_LOGDUMP_BYTES:-65536}"
TRAFFIC_POLL_INTERVAL_SECONDS="${TRAFFIC_POLL_INTERVAL_SECONDS:-2.0}"

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

echo "Starting stack..."
if [[ "${USE_SSL}" == "yes" && -n "${PANEL_DOMAIN}" ]]; then
  mkdir -p "${INSTALL_DIR}/deploy"
  cat >"${INSTALL_DIR}/deploy/Caddyfile" <<EOF
${PANEL_DOMAIN} {
  encode gzip
  reverse_proxy backend:8000
}
EOF
  docker compose -f "${INSTALL_DIR}/docker-compose.yml" --env-file "${INSTALL_DIR}/.env" --profile ssl up -d --build
else
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
if [[ "${USE_SSL}" == "yes" && -n "${PANEL_DOMAIN}" ]]; then
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
if [[ "${USE_SSL}" == "yes" && -n "${PANEL_DOMAIN}" ]]; then
  echo "If HTTPS is not available yet, check DNS A record for ${PANEL_DOMAIN} and open ports 80/443."
fi
