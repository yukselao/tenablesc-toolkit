#!/usr/bin/env bash
# Reset all stored data: wipe analysis history in MariaDB.
# Pass --hard to also destroy the DB volume (full re-init from init.sql).
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--hard" ]]; then
  echo "==> HARD reset: destroying database volume..."
  docker compose down -v
  echo "==> Recreating stack..."
  docker compose up -d --build
  echo "  ✅  Database volume recreated from scratch."
  exit 0
fi

echo "==> Resetting analysis history (TRUNCATE analyses)..."
if ! docker compose ps db --status running >/dev/null 2>&1; then
  echo "  ⚠️  DB container is not running. Start it first with ./start.sh"
  exit 1
fi

docker compose exec -T db \
  mariadb -unessus -pnessus nessus_compare \
  -e "TRUNCATE TABLE analyses;"

echo "  ✅  History cleared. (Use './reset-db.sh --hard' to rebuild the volume entirely.)"
