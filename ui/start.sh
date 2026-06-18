#!/usr/bin/env bash
# Bring the Nessus Compare UI up (web + MariaDB).
set -euo pipefail
cd "$(dirname "$0")"

PORT=8091

echo "==> Building and starting Nessus Compare UI..."
docker compose up -d --build

echo "==> Waiting for the web service to respond..."
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:${PORT}/" >/dev/null 2>&1; then
    echo
    echo "  ✅  UI is up:  http://localhost:${PORT}/"
    echo "      Sidebar → 'Compare Nessus Scans'"
    echo "      Test files: sample-data/compare-scenarios/{first-scan,last-scan}.nessus"
    exit 0
  fi
  sleep 1
done

echo "  ⚠️  Web service did not respond yet. Check logs:  docker compose logs -f web"
exit 1
