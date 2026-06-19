#!/bin/bash
# =============================================================
# CA-eBPF Experiment — Step 1: Install Dependencies
# Run on Ubuntu 22.04 EC2 instance as ubuntu user
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARNING: $1${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR: $1${NC}"; exit 1; }

log "=== CA-eBPF Experiment: Step 1 — Installing Dependencies ==="

# Verify Ubuntu 22.04
if ! lsb_release -d | grep -q "Ubuntu 22.04"; then
  warn "Not Ubuntu 22.04 — some steps may behave differently"
fi

# Verify minimum resources
TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
TOTAL_CPU=$(nproc)
log "System: ${TOTAL_CPU} vCPU, ${TOTAL_MEM}GB RAM"
[ "$TOTAL_MEM" -lt 14 ] && fail "Need at least 16GB RAM. Got ${TOTAL_MEM}GB. Use t3.2xlarge."
[ "$TOTAL_CPU" -lt 4 ]  && fail "Need at least 4 vCPUs. Got ${TOTAL_CPU}."

# ---- System update ----
log "Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# ---- Docker CE ----
log "Installing Docker CE..."
sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release apt-transport-https
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin
sudo usermod -aG docker "$USER"
sudo systemctl enable docker
sudo systemctl start docker
log "Docker installed: $(docker --version)"

# ---- kind ----
log "Installing kind v0.22.0..."
curl -fsSLo /tmp/kind \
  https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
sudo install -o root -g root -m 0755 /tmp/kind /usr/local/bin/kind
log "kind installed: $(kind --version)"

# ---- kubectl ----
log "Installing kubectl v1.29..."
curl -fsSLo /tmp/kubectl \
  "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl
log "kubectl installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"

# ---- Helm ----
log "Installing Helm v3..."
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
log "Helm installed: $(helm version --short)"

# ---- Python packages ----
log "Installing Python packages..."
sudo apt-get install -y -qq python3-pip python3-venv
pip3 install --quiet --break-system-packages \
  flask==3.0.0 \
  requests==2.31.0 \
  opentelemetry-api==1.21.0 \
  opentelemetry-sdk==1.21.0 \
  opentelemetry-instrumentation-flask==0.42b0 \
  opentelemetry-instrumentation-requests==0.42b0 \
  opentelemetry-exporter-otlp==1.21.0 \
  pandas==2.1.4 \
  numpy==1.26.2 \
  scikit-learn==1.3.2 \
  python-dateutil==2.8.2 \
  tqdm==4.66.1
log "Python packages installed"

# ---- jq and other tools ----
log "Installing utilities..."
sudo apt-get install -y -qq jq curl wget netcat-openbsd htop

# ---- Docker daemon config (increase resources for kind) ----
log "Configuring Docker daemon..."
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
  "default-shm-size": "1g",
  "default-ulimits": {
    "memlock": { "Hard": -1, "Name": "memlock", "Soft": -1 },
    "nofile": { "Hard": 65536, "Name": "nofile", "Soft": 65536 }
  }
}
EOF
sudo systemctl restart docker
sleep 5

# ---- Kernel parameters for kind/eBPF ----
log "Configuring kernel parameters..."
sudo tee /etc/sysctl.d/99-kind-ebpf.conf > /dev/null <<'EOF'
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
net.core.somaxconn=65535
kernel.perf_event_paranoid=0
EOF
sudo sysctl --system -q

# ---- Verify eBPF support ----
log "Verifying eBPF kernel support..."
KERNEL=$(uname -r | cut -d. -f1-2 | tr -d .)
if [ "$KERNEL" -ge "419" ]; then
  log "Kernel $(uname -r) supports eBPF ✓"
else
  fail "Kernel $(uname -r) too old for eBPF. Need 4.19+"
fi

log ""
log "=== Step 1 Complete ==="
log "IMPORTANT: Log out and back in for Docker group to take effect,"
log "OR run: newgrp docker"
log "Then run: ./02_create_cluster.sh"
