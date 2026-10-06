#!/usr/bin/env bash
#
# One-shot lab bootstrap: brings up the Docker stack, waits for each service
# to answer healthchecks, then runs the one-time setup calls that can't be
# baked into the images (TheHive org/user, Cortex analyzer activation keys,
# MISP automation API key). This is a convenience wrapper around the manual
# steps documented in docs/setup-guide.md — read that doc if any step here
# fails and you need to debug it by hand.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
  echo "No .env found — copying .env.example. Edit it with real secrets before continuing." >&2
  cp .env.example .env
  exit 1
fi

echo "==> Starting docker compose stack (this can take a few minutes on first pull)"
docker compose -f docker/docker-compose.yml up -d

wait_for() {
  local name="$1" url="$2" tries=60
  echo -n "==> Waiting for ${name} at ${url} "
  until curl -sk -o /dev/null "$url" || [ "$tries" -eq 0 ]; do
    echo -n "."
    sleep 5
    tries=$((tries - 1))
  done
  echo
  if [ "$tries" -eq 0 ]; then
    echo "   ${name} did not come up in time — check 'docker compose logs' for it." >&2
  else
    echo "   ${name} is up."
  fi
}

wait_for "Wazuh dashboard" "https://localhost:443"
wait_for "TheHive" "http://localhost:9000"
wait_for "Cortex" "http://localhost:9001"
wait_for "MISP" "https://localhost:8443"

echo "==> Base services are up."
echo "    Next manual steps (see docs/setup-guide.md for detail):"
echo "      1. Log into TheHive at http://localhost:9000, create the 'SOC' org + an API key."
echo "      2. Log into Cortex at http://localhost:9001, link it to TheHive, activate analyzers,"
echo "         and generate an API key for the 'soar_automation' user."
echo "      3. Log into MISP at https://localhost:8443, create a scoped automation API key."
echo "      4. Put all three keys into soar_automation/config.yaml (copy from config.example.yaml)."
echo "      5. Optionally run: python3 scripts/seed_misp.py"
echo "      6. Start the orchestrator: python3 -m soar_automation.main --config soar_automation/config.yaml"
