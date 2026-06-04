#!/usr/bin/env bash
set -euo pipefail

docker compose up -d --build
echo "[lab] started"
echo "[lab] target service: http://localhost:8080"
echo "[lab] vue dashboard: http://localhost:3000"
