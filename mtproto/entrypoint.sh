#!/bin/sh
set -eu

CONFIG_PATH="/config/config.toml"
CURRENT_HASH=""
CHILD_PID=""

start_mtg() {
  /usr/local/bin/mtg run "$CONFIG_PATH" &
  CHILD_PID="$!"
  echo "mtg started, pid=$CHILD_PID"
}

stop_mtg() {
  if [ -n "${CHILD_PID}" ] && kill -0 "${CHILD_PID}" 2>/dev/null; then
    kill "${CHILD_PID}" 2>/dev/null || true
    wait "${CHILD_PID}" 2>/dev/null || true
  fi
  CHILD_PID=""
}

trap 'stop_mtg; exit 0' INT TERM

while true; do
  if [ ! -f "$CONFIG_PATH" ]; then
    stop_mtg
    sleep 1
    continue
  fi

  NEW_HASH="$(sha256sum "$CONFIG_PATH" | awk '{print $1}')"
  if [ "$NEW_HASH" != "$CURRENT_HASH" ]; then
    echo "config changed, reloading mtg"
    stop_mtg
    CURRENT_HASH="$NEW_HASH"
    start_mtg
  fi

  if [ -n "${CHILD_PID}" ] && ! kill -0 "${CHILD_PID}" 2>/dev/null; then
    echo "mtg process exited, restarting"
    CHILD_PID=""
    start_mtg
  fi

  sleep 2
done
