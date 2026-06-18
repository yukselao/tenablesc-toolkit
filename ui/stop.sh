#!/usr/bin/env bash
# Stop the Nessus Compare UI (keeps the database volume / history intact).
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Stopping Nessus Compare UI..."
docker compose down
echo "  ✅  Stopped. Data preserved (use ./reset-db.sh to wipe history)."
