#!/bin/bash
# =============================================================
# CA-eBPF Fix — Ubuntu 26.04 + Python 3.14 compatibility
# Uses Miniforge to create a clean Python 3.12 environment
# =============================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR: $1${NC}"; exit 1; }

log "=== CA-eBPF Fix: Ubuntu 26.04 / Python 3.14 → Miniforge Python 3.12 ==="
log "Detected OS:     $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2)"
log "Detected Python: $(python3 --version)"

# ============================================================
# STEP 1 — Install Miniforge (conda-forge, free, no license)
# ============================================================
log ""
log "[1/6] Installing Miniforge..."

curl -fsSLo /tmp/miniforge.sh \
  https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh

bash /tmp/miniforge.sh -b -p "$HOME/miniforge3"
rm /tmp/miniforge.sh

# Init conda in .bashrc
"$HOME/miniforge3/bin/conda" init bash
export PATH="$HOME/miniforge3/bin:$PATH"

log "Miniforge installed: $($HOME/miniforge3/bin/conda --version)"

# ============================================================
# STEP 2 — Create Python 3.12 environment
# ============================================================
log ""
log "[2/6] Creating Python 3.12 conda environment (ca-ebpf-env)..."

"$HOME/miniforge3/bin/conda" create -n ca-ebpf-env python=3.12 -y -q

PYTHON="$HOME/miniforge3/envs/ca-ebpf-env/bin/python"
PIP="$HOME/miniforge3/envs/ca-ebpf-env/bin/pip"

log "Python 3.12: $($PYTHON --version)"

# ============================================================
# STEP 3 — Install all required packages
# ============================================================
log ""
log "[3/6] Installing Python packages into ca-ebpf-env..."

$PIP install --quiet --upgrade pip

$PIP install --quiet \
  flask==3.0.0 \
  requests==2.31.0 \
  opentelemetry-api==1.21.0 \
  opentelemetry-sdk==1.21.0 \
  "opentelemetry-instrumentation-flask==0.42b0" \
  "opentelemetry-instrumentation-requests==0.42b0" \
  "opentelemetry-exporter-otlp==1.21.0" \
  pandas==2.2.3 \
  numpy==1.26.4 \
  scikit-learn==1.4.2 \
  python-dateutil==2.9.0 \
  tqdm==4.66.4

log "Verifying packages..."
$PYTHON -c "
import pandas, numpy, sklearn, flask, requests
print(f'  pandas    {pandas.__version__}  ✓')
print(f'  numpy     {numpy.__version__}  ✓')
print(f'  sklearn   {sklearn.__version__}  ✓')
print(f'  flask     {flask.__version__}  ✓')
print(f'  requests  {requests.__version__}  ✓')
"

# ============================================================
# STEP 4 — Set conda env as default python3 for this user
# ============================================================
log ""
log "[4/6] Setting ca-ebpf-env as default python3..."

# Add to .bashrc so it persists across sessions
cat >> ~/.bashrc << 'EOF'

# CA-eBPF experiment — use conda env
export PATH="$HOME/miniforge3/envs/ca-ebpf-env/bin:$HOME/miniforge3/bin:$PATH"
EOF

export PATH="$HOME/miniforge3/envs/ca-ebpf-env/bin:$HOME/miniforge3/bin:$PATH"

log "python3 → $(which python3) → $(python3 --version)"

# ============================================================
# STEP 5 — Install Docker, kind, kubectl, Helm
# ============================================================
log ""
log "[5/6] Installing Docker CE..."

sudo apt-get update -qq
sudo apt-get install -y -qq \
  ca-certificates curl gnupg lsb-release \
  apt-transport-https jq wget netcat-openbsd

# Docker — detect correct repo for Ubuntu 26.04
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Ubuntu 26.04 "resolute" — use jammy repo as fallback
# if Docker doesn't have a resolute release yet
CODENAME=$(lsb_release -cs)
DOCKER_CODENAME="$CODENAME"
HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}" \
  "https://download.docker.com/linux/ubuntu/dists/${CODENAME}/Release" || echo "000")
if [ "$HTTP_STATUS" != "200" ]; then
  warn "No Docker repo for ${CODENAME} yet, using noble (24.04) as fallback..."
  DOCKER_CODENAME="noble"
fi

echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu ${DOCKER_CODENAME} stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -qq
sudo apt-get install -y -qq \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin

sudo usermod -aG docker "$USER"
sudo systemctl enable docker
sudo systemctl start docker
log "Docker: $(docker --version)"

# kind
log "Installing kind v0.22.0..."
curl -fsSLo /tmp/kind \
  https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
sudo install -o root -g root -m 0755 /tmp/kind /usr/local/bin/kind
log "kind: $(kind --version)"

# kubectl
log "Installing kubectl v1.29..."
curl -fsSLo /tmp/kubectl \
  "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl
log "kubectl: $(kubectl version --client 2>/dev/null | head -1)"

# Helm
log "Installing Helm..."
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
log "Helm: $(helm version --short)"

# ============================================================
# STEP 6 — System config for kind + eBPF
# ============================================================
log ""
log "[6/6] Configuring system for kind and eBPF..."

sudo tee /etc/docker/daemon.json > /dev/null << 'EOF'
{
  "default-shm-size": "1g",
  "default-ulimits": {
    "memlock": { "Hard": -1, "Name": "memlock", "Soft": -1 },
    "nofile":  { "Hard": 65536, "Name": "nofile", "Soft": 65536 }
  }
}
EOF
sudo systemctl restart docker
sleep 5

sudo tee /etc/sysctl.d/99-kind-ebpf.conf > /dev/null << 'EOF'
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
net.core.somaxconn=65535
kernel.perf_event_paranoid=0
EOF
sudo sysctl --system -q

# Verify kernel supports eBPF
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
log "Kernel: $(uname -r)"
[ "$KERNEL_MAJOR" -gt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 19 ]; } || \
  fail "Kernel too old for eBPF — need 4.19+"
log "eBPF support: ✓"

# ============================================================
# DONE
# ============================================================
log ""
log "========================================================"
log "  Fix Complete — All dependencies installed"
log "========================================================"
log ""
log "  Python 3.12 env : $HOME/miniforge3/envs/ca-ebpf-env"
log "  python3         : $(which python3) ($(python3 --version))"
log "  Docker          : $(docker --version | cut -d' ' -f1-3)"
log "  kind            : $(kind --version)"
log ""
log "  Run these TWO commands now, then continue:"
log ""
log "    source ~/.bashrc"
log "    newgrp docker"
log ""
log "  Then run Step 2:"
log "    bash scripts/02_create_cluster.sh"
