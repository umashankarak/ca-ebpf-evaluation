#!/bin/bash
# =============================================================
# CA-eBPF Experiment — Step 3: Build Images + Deploy Services
# =============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVICES_DIR="$PROJECT_DIR/services"
MANIFESTS_DIR="$PROJECT_DIR/manifests"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR: $1${NC}"; exit 1; }

log "=== CA-eBPF Experiment: Step 3 — Build and Deploy ==="

# Verify cluster is running
kubectl cluster-info --context kind-ca-ebpf-cluster &>/dev/null || \
  fail "Cluster not running. Run step 2 first."

kubectl wait --for=condition=Ready nodes --all --timeout=60s || \
  fail "Nodes not ready"

# ---- Build Docker images ----
log "Building Docker images for all 4 microservices..."

declare -A SERVICES=(
    ["order-service"]="order_service.py"
    ["payment-service"]="payment_service.py"
    ["user-profile-service"]="user_profile_service.py"
    ["admin-service"]="admin_service.py"
)

for SERVICE_NAME in "${!SERVICES[@]}"; do
    SERVICE_FILE="${SERVICES[$SERVICE_NAME]}"
    IMAGE_TAG="ca-ebpf/${SERVICE_NAME}:latest"

    log "  Building ${IMAGE_TAG}..."
    docker build \
        --build-arg SERVICE_FILE="$SERVICE_FILE" \
        -t "$IMAGE_TAG" \
        -f "$SERVICES_DIR/Dockerfile" \
        "$SERVICES_DIR" \
        --quiet

    log "  Loading ${IMAGE_TAG} into kind cluster..."
    kind load docker-image "$IMAGE_TAG" \
        --name ca-ebpf-cluster
done

log "All images built and loaded ✓"
docker images | grep ca-ebpf

# ---- Apply Kubernetes manifests ----
log "Applying Kubernetes manifests..."
kubectl apply -f "$MANIFESTS_DIR/k8s-manifests.yaml"

# ---- Apply Tetragon TracingPolicy ----
log "Applying Tetragon TracingPolicy..."
# Check if Tetragon CRD is available
if kubectl get crd tracingpolicies.cilium.io &>/dev/null; then
    kubectl apply -f "$MANIFESTS_DIR/tetragon-policy.yaml"
    log "Tetragon TracingPolicy applied ✓"
else
    warn "Tetragon CRD not found — eBPF policies will use base configuration"
fi

# ---- Wait for deployments ----
log "Waiting for all deployments to be ready (up to 3 minutes)..."
DEPLOYMENTS=("order-service" "payment-service" "user-profile-service" "admin-service")

for DEP in "${DEPLOYMENTS[@]}"; do
    log "  Waiting for $DEP..."
    kubectl rollout status deployment/"$DEP" \
        -n production \
        --timeout=180s || fail "$DEP deployment failed"
done

# ---- Verify pods ----
log "Verifying pod status..."
kubectl get pods -n production -o wide

# ---- Verify services ----
log "Verifying service endpoints..."
kubectl get services -n production

# ---- Smoke test ----
log "Running service health checks..."

# Find a pod to run tests from
TEST_POD=$(kubectl get pods -n production -l app=order-service \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$TEST_POD" ]; then
    for SVC_NAME in "order-service:5000" "payment-service:5001" "user-profile-service:5002" "admin-service:5003"; do
        SVC=$(echo "$SVC_NAME" | cut -d: -f1)
        PORT=$(echo "$SVC_NAME" | cut -d: -f2)
        RESULT=$(kubectl exec "$TEST_POD" -n production -- \
            curl -sf "http://${SVC}:${PORT}/health" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" \
            2>/dev/null || echo "unreachable")
        if [ "$RESULT" = "healthy" ]; then
            log "  $SVC health: ✓ healthy"
        else
            warn "  $SVC health: $RESULT"
        fi
    done
else
    warn "Could not find test pod for smoke test"
fi

# ---- Start Tetragon event streaming ----
log "Starting Tetragon event capture in background..."
mkdir -p "$PROJECT_DIR/collect/raw"

TETRAGON_POD=$(kubectl get pods -n kube-system \
    -l app.kubernetes.io/name=tetragon \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$TETRAGON_POD" ]; then
    # Start streaming Tetragon events to file (background)
    kubectl exec -n kube-system "$TETRAGON_POD" -c tetragon -- \
        tetra getevents -o json --namespace production \
        > "$PROJECT_DIR/collect/raw/tetragon_events.jsonl" 2>/dev/null &
    TETRAGON_PID=$!
    echo "$TETRAGON_PID" > "$PROJECT_DIR/collect/raw/tetragon_stream.pid"
    log "Tetragon event streaming started (PID: $TETRAGON_PID) → collect/raw/tetragon_events.jsonl"
else
    warn "Tetragon pod not found — will collect events via kubectl exec in step 4"
fi

log ""
log "=== Step 3 Complete ==="
log "Services deployed: order-service, payment-service, user-profile-service, admin-service"
log "Tetragon:          Capturing eBPF events"
log "Next:              Run ./04_run_experiment.sh"
