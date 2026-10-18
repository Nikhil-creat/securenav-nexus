#!/usr/bin/env bash
# Runs every adversarial scenario against the running compose stack and prints IDS/e-stop outcome.
set -euo pipefail
SCENARIOS=(dos rogue spoof gps_denial)
for s in "${SCENARIOS[@]}"; do
  echo "=== scenario: $s ==="
  docker compose exec -T sec-ids-guardian bash -lc "python3 -m sim.fault_injector $s --duration 10" || true
  sleep 3
  docker compose logs --since 20s sec-ids-guardian | grep -E 'threat detected' | tail -n 3 || echo "  (no detection logged)"
  docker compose exec -T sec-ids-guardian bash -lc "ros2 topic echo /sys/e_stop --once" || true
  docker compose exec -T hsm-emulator-node python3 -c "from security_nodes.hsm_emulator import HsmClient;print(HsmClient('/run/nexus/hsm.sock').call({'op':'revoked'}))" || true
done
