# CA-eBPF Real Kubernetes Data Collection
## Complete Setup Guide for AWS EC2

This project generates **real** Kubernetes eBPF telemetry data from a live kind cluster
running on AWS EC2. All data is produced from actual kernel-level observations via
Cilium Tetragon, making it fully legitimate for MDPI submission.

---

## EC2 Instance Requirements

| Parameter       | Value                         |
|-----------------|-------------------------------|
| Instance Type   | t3.2xlarge (8 vCPU, 32GB RAM) |
| AMI             | Ubuntu 22.04 LTS (64-bit x86) |
| Storage         | 40 GB gp3                     |
| Security Group  | Allow SSH (22) from your IP   |
| IAM Role        | None required                 |

### Launch via AWS Console
1. Go to EC2 → Launch Instance
2. Select Ubuntu 22.04 LTS
3. Choose t3.2xlarge
4. Set storage to 40 GB gp3
5. Create/select a key pair (.pem file)
6. Launch

### Launch via AWS CLI
```bash
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \
  --instance-type t3.2xlarge \
  --key-name YOUR_KEY_PAIR_NAME \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ca-ebpf-experiment}]'
```
> Note: AMI ID shown is for us-east-1. Find your region's Ubuntu 22.04 AMI at:
> https://cloud-images.ubuntu.com/locator/ec2/

---

## Step-by-Step Execution Order

Run each script in order. Each step validates before proceeding.

```
Step 1:  01_install_dependencies.sh    (~10 min)
Step 2:  02_create_cluster.sh          (~5 min)
Step 3:  03_build_and_deploy.sh        (~10 min)
Step 4:  04_run_experiment.sh          (~60 min)
Step 5:  05_collect_and_export.sh      (~5 min)
```

Total time: ~90 minutes. Estimated EC2 cost: ~$0.70

---

## What Each Step Does

### Step 1 — Install Dependencies
- Docker CE
- kind v0.22.0
- kubectl v1.29
- Helm v3
- Python 3 + packages (requests, flask, opentelemetry)

### Step 2 — Create Cluster
- Creates a 4-node kind cluster (1 control-plane + 3 workers)
- Installs Cilium Tetragon via Helm for eBPF telemetry
- Installs metrics-server
- Verifies all nodes are Ready

### Step 3 — Build and Deploy Services
- Builds 4 Python Flask microservice Docker images locally
- Loads images into kind (no registry needed)
- Deploys: order-service, payment-service, user-profile-service, admin-service
- Creates Kubernetes service accounts, NetworkPolicies, Tetragon TracingPolicy
- Verifies all pods are Running

### Step 4 — Run Experiment (60 min)
- Phase 1 (20 min): Normal traffic only (generates BENIGN events)
- Phase 2 (20 min): Normal traffic + obvious attacks (generates OBVIOUS_ATTACK events)
- Phase 3 (20 min): Normal traffic + stealth attacks (generates STEALTH_ATTACK events)
- Attack log saved to: experiment/attack_timestamps.json

### Step 5 — Collect and Export
- Streams all Tetragon events from cluster
- Collects structured service logs from all pods
- Collects Kubernetes API metadata
- Processes raw telemetry into feature CSV
- Outputs: real_cluster_dataset.csv (matches S1 schema exactly)

---

## Output Files

After Step 5 completes, you will have:

```
collect/output/
├── raw_tetragon_events.jsonl        Raw Tetragon JSON events
├── raw_service_logs.jsonl           Structured service logs from all pods
├── raw_k8s_events.json              Kubernetes API events
├── attack_timestamps.json           Ground truth attack injection log
├── real_cluster_dataset.csv         Final processed CSV (upload to MDPI as S1-real)
└── real_cluster_metrics.csv         Aggregate metrics summary
```

---

## Data Schema

The output CSV matches the synthetic evaluation schema exactly:

| Column                  | Source                           |
|-------------------------|----------------------------------|
| event_id                | Sequential                       |
| event_type              | Derived from attack_timestamps   |
| log_message             | Service structured log           |
| trust_score             | Computed from telemetry          |
| identity_valid          | Service account token validation |
| runtime_anomaly         | Tetragon process_exec events     |
| trace_path_consistent   | Service log trace chain          |
| invocation_frequency    | Request rate per time window     |
| namespace_violation     | Tetragon network + K8s policy    |
| process_anomaly         | Unexpected binary execution      |
| connection_score        | Connection stability metrics     |
| ground_truth_label      | 0=benign, 1=attack               |

---

## Reproducibility

All experiments use:
- Fixed random seed where applicable
- Logged attack injection timestamps
- Deterministic traffic patterns
- All raw data preserved in collect/output/

Reviewers can verify any row in real_cluster_dataset.csv against the
corresponding entry in raw_tetragon_events.jsonl using the event_id.
