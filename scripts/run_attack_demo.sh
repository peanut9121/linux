#!/usr/bin/env bash
set -euo pipefail

docker compose exec attacker bash /lab/attack_demo.sh
echo
docker compose exec defender python /app/analyzer.py
