#!/usr/bin/env bash
# ============================================================
# SentiSOC — Brute Force Simulation
# Sends 10 failed login attempts to trigger the BruteForceDetected alert
# Usage: ./scripts/simulate-brute-force.sh [BASE_URL]
# ============================================================

BASE="${1:-http://localhost:5001}"
echo "Simulating brute force attack against $BASE"
echo "Sending 10 failed login attempts..."

for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"wrongpass_$i\"}")
  echo "  Attempt $i: HTTP $STATUS"
  sleep 0.5
done

echo ""
echo "Done. Check Grafana → BruteForceDetected alert (if 5+ attempts/min rule fired)."
echo "Grafana: http://localhost:3000"
echo "Auth metrics: $BASE/metrics"
