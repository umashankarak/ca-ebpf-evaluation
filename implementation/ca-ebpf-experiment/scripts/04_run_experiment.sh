#!/bin/bash
# =============================================================
# CA-eBPF Experiment — Step 4: Run Full Experiment
#
# Timeline:
#   Phase 1: 00:00 - 20:00  Normal traffic only        (BENIGN)
#   Phase 2: 20:00 - 40:00  Normal traffic + obvious attacks
#   Phase 3: 40:00 - 60:00  Normal traffic + stealth attacks
# =============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXPERIMENT_DIR="$PROJECT_DIR/experiment"
COLLECT_DIR="$PROJECT_DIR/collect/raw"
NAMESPACE="production"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()   { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
phase() { echo -e "${BLUE}[$(date +%H:%M:%S)] === $1 ===${NC}"; }
warn()  { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }

log "=== CA-eBPF Experiment: Step 4 — Running Full Experiment ==="
log "Total duration: ~60 minutes"
log "Start time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$COLLECT_DIR"

# Record experiment start time
echo "{\"experiment_start\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
  > "$COLLECT_DIR/experiment_meta.json"

# Find an order-service pod to run traffic generators from
ORDER_POD=$(kubectl get pods -n "$NAMESPACE" -l app=order-service \
  -o jsonpath='{.items[0].metadata.name}')
log "Using pod: $ORDER_POD for traffic generation"

# Start Tetragon event collection (restart fresh)
TETRAGON_POD=$(kubectl get pods -n kube-system \
  -l app.kubernetes.io/name=tetragon \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$TETRAGON_POD" ]; then
  log "Starting fresh Tetragon event capture..."
  # Kill any existing tetra stream
  kill "$(cat "$COLLECT_DIR/tetragon_stream.pid" 2>/dev/null || echo 0)" 2>/dev/null || true

  kubectl exec -n kube-system "$TETRAGON_POD" -c tetragon -- \
    tetra getevents -o json --namespace "$NAMESPACE" \
    > "$COLLECT_DIR/tetragon_events.jsonl" 2>/dev/null &
  echo $! > "$COLLECT_DIR/tetragon_stream.pid"
  log "Tetragon streaming → collect/raw/tetragon_events.jsonl (PID: $(cat "$COLLECT_DIR/tetragon_stream.pid"))"
  sleep 3
fi

# ============================================================
# PHASE 1 — Normal traffic only (20 minutes)
# ============================================================
phase "PHASE 1 / 3 — Normal traffic only (0:00 - 20:00)"
echo "{\"phase1_start\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$COLLECT_DIR/experiment_meta.json"

# Copy traffic generator into the pod
kubectl cp "$EXPERIMENT_DIR/generate_traffic.py" \
  "$NAMESPACE/$ORDER_POD:/tmp/generate_traffic.py"

# Run traffic generator in background (inside pod)
kubectl exec -n "$NAMESPACE" "$ORDER_POD" -- \
  python3 /tmp/generate_traffic.py \
    --duration 1200 \
    --rps 2.5 \
    --output /tmp/phase1_traffic.log &
PHASE1_PID=$!

log "Phase 1 traffic running (PID: $PHASE1_PID)..."
log "Generating normal east-west traffic for 20 minutes..."

# Wait for phase 1 to complete
wait $PHASE1_PID || true
kubectl cp "$NAMESPACE/$ORDER_POD:/tmp/phase1_traffic.log" \
  "$COLLECT_DIR/phase1_traffic.log" 2>/dev/null || true

echo "{\"phase1_end\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$COLLECT_DIR/experiment_meta.json"
log "Phase 1 complete ✓"

# ============================================================
# PHASE 2 — Normal traffic + obvious attacks (20 minutes)
# ============================================================
phase "PHASE 2 / 3 — Normal traffic + obvious attacks (20:00 - 40:00)"
echo "{\"phase2_start\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$COLLECT_DIR/experiment_meta.json"

# Copy attack injector into pod
kubectl cp "$EXPERIMENT_DIR/inject_attacks.py" \
  "$NAMESPACE/$ORDER_POD:/tmp/inject_attacks.py"

# Run background normal traffic during phase 2
kubectl exec -n "$NAMESPACE" "$ORDER_POD" -- \
  python3 /tmp/generate_traffic.py \
    --duration 1200 \
    --rps 2.0 \
    --output /tmp/phase2_traffic.log &
PHASE2_TRAFFIC_PID=$!

# Run obvious attacks (runs for ~10 minutes, interspersed with pauses)
log "Injecting obvious attacks..."
kubectl exec -n "$NAMESPACE" "$ORDER_POD" -- \
  python3 /tmp/inject_attacks.py \
    --mode obvious \
    --output /tmp/phase2_attack_log.json &
PHASE2_ATTACK_PID=$!

# Let both run; attack injector finishes faster, traffic continues
wait $PHASE2_ATTACK_PID || true

# Copy attack log from pod
kubectl cp "$NAMESPACE/$ORDER_POD:/tmp/phase2_attack_log.json" \
  "$COLLECT_DIR/phase2_attack_log.json" 2>/dev/null || true

# Wait remainder of 20 minutes
ELAPSED=$(($(date +%s) - $(date -d "$(date -u +%Y-%m-%dT%H:%M:%SZ)" +%s 2>/dev/null || echo $(date +%s))))
REMAINING=$((1200 - ELAPSED < 0 ? 0 : 1200 - ELAPSED))
[ $REMAINING -gt 0 ] && sleep $REMAINING

kill $PHASE2_TRAFFIC_PID 2>/dev/null || true
kubectl cp "$NAMESPACE/$ORDER_POD:/tmp/phase2_traffic.log" \
  "$COLLECT_DIR/phase2_traffic.log" 2>/dev/null || true

echo "{\"phase2_end\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$COLLECT_DIR/experiment_meta.json"
log "Phase 2 complete ✓"

# ============================================================
# PHASE 3 — Normal traffic + stealth attacks (20 minutes)
# ============================================================
phase "PHASE 3 / 3 — Normal traffic + stealth attacks (40:00 - 60:00)"
echo "{\"phase3_start\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$COLLECT_DIR/experiment_meta.json"

# Run background traffic
kubectl exec -n "$NAMESPACE" "$ORDER_POD" -- \
  python3 /tmp/generate_traffic.py \
    --duration 1200 \
    --rps 2.5 \
    --output /tmp/phase3_traffic.log &
PHASE3_TRAFFIC_PID=$!

# Run stealth attacks
log "Injecting stealth attacks..."
kubectl exec -n "$NAMESPACE" "$ORDER_POD" -- \
  python3 /tmp/inject_attacks.py \
    --mode stealth \
    --output /tmp/phase3_attack_log.json &
PHASE3_ATTACK_PID=$!

wait $PHASE3_ATTACK_PID || true
kubectl cp "$NAMESPACE/$ORDER_POD:/tmp/phase3_attack_log.json" \
  "$COLLECT_DIR/phase3_attack_log.json" 2>/dev/null || true

ELAPSED2=$(($(date +%s) - $(date -d "$(date -u +%Y-%m-%dT%H:%M:%SZ)" +%s 2>/dev/null || echo $(date +%s))))
REMAINING2=$((1200 - ELAPSED2 < 0 ? 0 : 1200 - ELAPSED2))
[ $REMAINING2 -gt 0 ] && sleep $REMAINING2

kill $PHASE3_TRAFFIC_PID 2>/dev/null || true
kubectl cp "$NAMESPACE/$ORDER_POD:/tmp/phase3_traffic.log" \
  "$COLLECT_DIR/phase3_traffic.log" 2>/dev/null || true

echo "{\"phase3_end\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"experiment_end\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
  >> "$COLLECT_DIR/experiment_meta.json"

# Stop Tetragon stream
kill "$(cat "$COLLECT_DIR/tetragon_stream.pid" 2>/dev/null || echo 0)" 2>/dev/null || true
log "Tetragon event collection stopped"

# Collect service logs from all pods
log "Collecting service logs from all pods..."
for SVC in order-service payment-service user-profile-service admin-service; do
  kubectl logs -n "$NAMESPACE" \
    -l "app=$SVC" \
    --since=2h \
    2>/dev/null \
    > "$COLLECT_DIR/${SVC}_logs.jsonl" || true
done

# Collect K8s events
kubectl get events -n "$NAMESPACE" -o json \
  > "$COLLECT_DIR/k8s_events.json" 2>/dev/null || true

log ""
log "=== Step 4 Complete ==="
log "Raw data collected in: collect/raw/"
ls -lh "$COLLECT_DIR/"
log "Next: Run ./05_collect_and_export.sh to process into CSV"
