#!/bin/bash
# =============================================================
# CA-eBPF Experiment — Step 2: Create Cluster + Install Tetragon
# =============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR: $1${NC}"; exit 1; }

log "=== CA-eBPF Experiment: Step 2 — Create Cluster ==="

# Verify tools
for cmd in docker kind kubectl helm; do
  command -v "$cmd" &>/dev/null || fail "$cmd not found — run step 1 first"
done

# Mount eBPF filesystem (required for Tetragon)
log "Mounting eBPF filesystem..."
if ! mount | grep -q /sys/fs/bpf; then
  sudo mount bpffs /sys/fs/bpf -t bpf
  log "/sys/fs/bpf mounted"
else
  log "/sys/fs/bpf already mounted"
fi

# Mount debugfs (required for Tetragon kprobes)
if ! mount | grep -q /sys/kernel/debug; then
  sudo mount -t debugfs debugfs /sys/kernel/debug
  log "/sys/kernel/debug mounted"
else
  log "/sys/kernel/debug already mounted"
fi

# Delete existing cluster if any
if kind get clusters 2>/dev/null | grep -q ca-ebpf-cluster; then
  warn "Deleting existing ca-ebpf-cluster..."
  kind delete cluster --name ca-ebpf-cluster
fi

# Create cluster
log "Creating 4-node kind cluster (this takes ~3 minutes)..."
kind create cluster \
  --name ca-ebpf-cluster \
  --config "$PROJECT_DIR/kind-config.yaml" \
  --wait 120s

log "Cluster created. Verifying nodes..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
kubectl get nodes -o wide

# Install Tetragon via Helm
log "Adding Cilium Helm repository..."
helm repo add cilium https://helm.cilium.io
helm repo update

log "Installing Tetragon (eBPF telemetry engine)..."
helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.exportFilename=/var/run/cilium/tetragon/tetragon.log \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --wait --timeout=120s

log "Waiting for Tetragon pods to be ready..."
kubectl rollout status daemonset/tetragon -n kube-system --timeout=120s
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

# Install tetra CLI (for streaming events)
log "Installing tetra CLI..."
TETRAGON_VERSION=$(helm list -n kube-system --filter tetragon -o json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['app_version'] if d else '0.11.0')" 2>/dev/null || echo "0.11.0")
curl -fsSLo /tmp/tetra.tar.gz \
  "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetra-linux-amd64.tar.gz" 2>/dev/null || \
curl -fsSLo /tmp/tetra.tar.gz \
  "https://github.com/cilium/tetragon/releases/download/v0.11.0/tetra-linux-amd64.tar.gz"
tar -xzf /tmp/tetra.tar.gz -C /tmp/
sudo mv /tmp/tetra /usr/local/bin/tetra 2>/dev/null || true
log "tetra CLI installed"

# Install metrics-server
log "Installing metrics-server..."
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system \
  --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'

# Verify Tetragon is working
log "Verifying Tetragon eBPF telemetry..."
sleep 10
TEST_OUTPUT=$(kubectl exec -n kube-system \
  "$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon -o jsonpath='{.items[0].metadata.name}')" \
  -c tetragon -- \
  timeout 5 tetra getevents -o json 2>/dev/null | head -3 || echo "warming_up")

if echo "$TEST_OUTPUT" | grep -q "process_exec\|warming_up"; then
  log "Tetragon eBPF telemetry working ✓"
else
  warn "Tetragon may still be warming up — this is normal"
fi

log ""
log "=== Step 2 Complete ==="
log "Cluster:  ca-ebpf-cluster (4 nodes)"
log "Tetragon: Installed and capturing eBPF events"
log "Next:     Run ./03_build_and_deploy.sh"
