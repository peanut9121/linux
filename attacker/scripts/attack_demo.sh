#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${TARGET_HOST:-target}"
TARGET_PORT="${TARGET_PORT:-8080}"

echo "[attacker] controlled demo started"
echo "[attacker] target=${TARGET_HOST}:${TARGET_PORT}"

echo "[attacker] ping target"
ping -c 2 "${TARGET_HOST}" || true

echo "[attacker] simulate repeated web requests"
for path in / /login /admin /debug /health; do
  curl -sS "http://${TARGET_HOST}:${TARGET_PORT}${path}" >/dev/null || true
  sleep 1
done

echo "[attacker] simulate failed login attempts"
for user in root admin test guest; do
  curl -sS "http://${TARGET_HOST}:${TARGET_PORT}/login?user=${user}&result=failed" >/dev/null || true
  sleep 1
done

echo "[attacker] controlled demo finished"
