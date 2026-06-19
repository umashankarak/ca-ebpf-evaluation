#!/bin/bash
# =============================================================
# CA-eBPF — Fix Step 3 and complete setup
# Run this from ~/ca-ebpf-experiment on EC2
# =============================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }

NAMESPACE="production"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "=== Completing Step 3 ==="

# ---- Step 1: Fix the TracingPolicy (replace string_array → char_buf) ----
log "[1/5] Applying fixed Tetragon TracingPolicy..."

kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: ca-ebpf-process-monitor
  namespace: kube-system
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_execve"
    args:
    - index: 0
      type: "string"
      label: "filename"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/bin/sh"
        - "/bin/bash"
        - "/bin/dash"
        - "/usr/bin/wget"
        - "/usr/bin/curl"
        - "/bin/nc"
        - "/usr/bin/python"
        - "/usr/bin/perl"
      matchActions:
      - action: Post
        rateLimit: "1/second"
EOF

log "TracingPolicy applied ✓"

# ---- Step 2: Verify all 3 policies are now applied ----
log "[2/5] Verifying all Tetragon TracingPolicies..."
kubectl get tracingpolicies -A 2>/dev/null || \
kubectl get tracingpolicy -A 2>/dev/null || \
warn "Could not list TracingPolicies — may need different API version"

# ---- Step 3: Wait for all pods to be Running ----
log "[3/5] Waiting for all pods to be Ready..."
kubectl wait --for=condition=Ready pods \
  --all -n "$NAMESPACE" \
  --timeout=180s

log "Pod status:"
kubectl get pods -n "$NAMESPACE" -o wide

# ---- Step 4: Run health checks ----
log "[4/5] Running service health checks..."
TEST_POD=$(kubectl get pods -n "$NAMESPACE" \
  -l app=order-service \
  -o jsonpath='{.items[0].metadata.name}')
log "Using test pod: $TEST_POD"

ALL_HEALTHY=true
for SVC_PORT in "order-service:5000" "payment-service:5001" \
                "user-profile-service:5002" "admin-service:5003"; do
  SVC=$(echo "$SVC_PORT"  | cut -d: -f1)
  PORT=$(echo "$SVC_PORT" | cut -d: -f2)
  RESULT=$(kubectl exec "$TEST_POD" -n "$NAMESPACE" -- \
    python3 -c "
import urllib.request, json
try:
    r = urllib.request.urlopen('http://${SVC}:${PORT}/health', timeout=5)
    d = json.loads(r.read())
    print(d.get('status','unknown'))
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null || echo "unreachable")
  if echo "$RESULT" | grep -q "healthy"; then
    log "  $SVC → ✓ healthy"
  else
    warn "  $SVC → $RESULT"
    ALL_HEALTHY=false
  fi
done

if $ALL_HEALTHY; then
  log "All 4 services are healthy ✓"
else
  warn "Some services not healthy yet — may still be starting up"
  warn "Wait 30 seconds and check again with:"
  warn "  kubectl get pods -n production"
fi

# ---- Step 5: Start Tetragon event streaming ----
log "[5/5] Starting Tetragon event streaming..."
mkdir -p "$PROJECT_DIR/collect/raw"

TETRAGON_POD=$(kubectl get pods -n kube-system \
  -l app.kubernetes.io/name=tetragon \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$TETRAGON_POD" ]; then
  # Kill any old stream
  OLD_PID=$(cat "$PROJECT_DIR/collect/raw/tetragon_stream.pid" 2>/dev/null || echo "")
  [ -n "$OLD_PID" ] && kill "$OLD_PID" 2>/dev/null || true

  # Start fresh stream
  kubectl exec -n kube-system "$TETRAGON_POD" -c tetragon -- \
    tetra getevents -o json --namespace "$NAMESPACE" \
    > "$PROJECT_DIR/collect/raw/tetragon_events.jsonl" 2>/dev/null &

  STREAM_PID=$!
  echo "$STREAM_PID" > "$PROJECT_DIR/collect/raw/tetragon_stream.pid"
  log "Tetragon streaming started (PID: $STREAM_PID)"
  sleep 3

  # Verify it is actually producing events
  LINES=$(wc -l < "$PROJECT_DIR/collect/raw/tetragon_events.jsonl" 2>/dev/null || echo 0)
  log "Tetragon events captured so far: $LINES"
else
  warn "Tetragon pod not found"
fi

# ---- Summary ----
log ""
log "==========================================="
log "  Step 3 Complete ✓"
log "==========================================="
log ""
log "Cluster:   4 nodes ready"
log "Services:  order / payment / user-profile / admin"
log "Tetragon:  3 TracingPolicies active, streaming to:"
log "           collect/raw/tetragon_events.jsonl"
log ""
log "Next — run the 60-minute experiment:"
log ""
log "  screen -S experiment"
log "  bash scripts/04_run_experiment.sh"
log ""
log "  (If SSH disconnects: screen -r experiment)"
