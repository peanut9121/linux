#!/usr/bin/env bash
set -euo pipefail

docker compose ps
echo
docker network inspect linux_lab_net --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}' 2>/dev/null || true
