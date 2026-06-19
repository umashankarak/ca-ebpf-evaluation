# Supplementary Materials

**Paper:** Multi-Signal Trust Scoring for Cloud-Native Microservice Security:
An eBPF-Based Framework for Stealth Attack Detection Without Sidecar Proxies

**Author:** Umashankara Kalaiah
**ORCID:** 0009-0000-5030-6751
**Contact:** umashankarak@gmail.com

---

## Overview

This archive contains all datasets, evaluation code, raw telemetry, ground
truth files, system provenance, and prototype implementation artifacts
supporting the experimental results reported in the manuscript. The
materials enable independent verification of every numerical claim in the
paper, including the simulation study (Section 9.1) and the real-cluster
validation (Section 9.2).

All simulation results are reproducible by executing `ca_ebpf_evaluation.py`
with NumPy random seed 42 on the dataset in S1.

---

## Two-Part Structure

The supplementary materials are organised into two groups:

**S1–S7 — Simulation Study Artifacts**
Synthetic 5,000-event dataset, per-event predictions for all five detection
approaches, aggregate metrics, sensitivity analyses, ROC curve data, and
trust score component breakdowns. These materials support the comparative
effectiveness evaluation reported in Section 9.1.

**S8–S13 — Real Kubernetes Cluster Validation Artifacts**
Real-cluster dataset derived from Cilium Tetragon eBPF observations, raw
Tetragon event log, telemetry processing report, attack injection ground
truth files, and system provenance. These materials support the
deployability validation reported in Section 9.2.

**S14 — Prototype Implementation**
Complete eBPF source code, Kubernetes manifests, microservice
implementations, traffic generation scripts, attack injection scripts, and
telemetry processing pipeline enabling independent replication of the
prototype deployment.

---

## File Index

### Simulation Study (S1–S7)

| ID  | Filename                          | Description                                                                          | Format |
|-----|-----------------------------------|--------------------------------------------------------------------------------------|--------|
| S1  | `S1_synthetic_dataset.csv`        | 5,000 simulated communication events with six telemetry features and ground-truth labels (3,800 benign, 700 obvious, 500 stealth) | CSV    |
| S2  | `S2_per_event_predictions.csv`    | Per-event binary predictions and continuous risk scores for all five detection approaches (logs-only, identity-only, anomaly-only, identity+anomaly, CA-eBPF) | CSV    |
| S3  | `S3_aggregate_metrics.csv`        | Computed accuracy, precision, recall, F1, AUC-ROC, and per-category detection rates for all five approaches (matches Tables 6 and 8 in the manuscript) | CSV    |
| S4  | `S4_sensitivity_analysis.csv`     | Threshold sweep (0.30–0.85) and weight configuration evaluation results (matches Table 10 in the manuscript) | CSV    |
| S5  | `S5_threshold_sweep_detail.csv`   | Per-threshold precision, recall, F1, and per-category detection rates at fine threshold granularity, supporting Figure 8a | CSV    |
| S6  | `S6_roc_curve_data.csv`           | (FPR, TPR) coordinate pairs across all threshold values for each of the five detection approaches, supporting Figure 5 | CSV    |
| S7  | `S7_trust_score_components.csv`   | Per-event values of the five trust score components (Iv, Bc, Nt, Pc, Tr), the runtime anomaly penalty (Ra), and the final trust score (Ts) | CSV    |

### Real Kubernetes Cluster Validation (S8–S13)

| ID   | Filename                                          | Description                                                                          | Format     |
|------|---------------------------------------------------|--------------------------------------------------------------------------------------|------------|
| S8   | `S8_real_cluster_dataset.csv`                     | 1,200 windowed feature records derived from 58,186 raw Tetragon kprobe events using 10-second aggregation windows (1,101 benign, 3 obvious, 96 stealth) | CSV        |
| S9   | `S9_tetragon_events.jsonl.gz`                     | Raw Cilium Tetragon eBPF event log captured during the 66-minute three-phase experiment (5.3 MB compressed, 258 MB uncompressed; one JSON object per line) | JSONL/gzip |
| S10  | `S10_processing_report.json`                      | Pipeline processing metadata: raw event counts, telemetry coverage notes, window aggregation parameters, and trust scoring configuration | JSON       |
| S11  | `S11_phase2_obvious_attacks_ground_truth.json`    | Phase 2 attack injection ground truth: six obvious attack scenarios with ISO 8601 start/end timestamps (token replay, unknown identity, cross-namespace, admin direct access, burst flood, privilege escalation) | JSON       |
| S12  | `S12_phase3_stealth_attacks_ground_truth.json`    | Phase 3 attack injection ground truth: five stealth attack scenarios with ISO 8601 start/end timestamps (slow credential abuse, trace path anomaly, low-frequency enumeration, intermittent probe, identity mimicry) | JSON       |
| S13  | `S13_system_provenance.json`                      | Full system provenance: AWS EC2 instance type, OS version, kernel version, kind version, Kubernetes version, Cilium Tetragon version | JSON       |

### Prototype Implementation (S14)

| ID  | Filename                              | Description                                                                          | Format |
|-----|---------------------------------------|--------------------------------------------------------------------------------------|--------|
| S14 | `S14_prototype_implementation/`       | Complete prototype source tree (see structure below)                                | Folder |