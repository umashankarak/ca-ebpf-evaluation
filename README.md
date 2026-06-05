# Context-Aware eBPF Trust Boundary Enforcement (CA-eBPF)

## Overview

Context-Aware eBPF Trust Boundary Enforcement (CA-eBPF) is a research prototype that explores sidecar-less trust-boundary enforcement for cloud-native microservice environments. The framework leverages contextual telemetry, workload identity validation, behavioral anomaly detection, and trust scoring concepts inspired by eBPF-based observability systems to improve runtime security decisions without relying on service mesh sidecar proxies.

Traditional microservice security solutions often depend on service meshes such as Istio or Linkerd to enforce security policies. While effective, these approaches introduce additional operational complexity, resource consumption, and deployment overhead. CA-eBPF investigates an alternative model in which contextual runtime information is used to evaluate trust relationships between services and identify unauthorized communication patterns.

This repository contains the experimental evaluation artifacts used to validate the trust-boundary enforcement model presented in the paper:

> **Context-Aware eBPF Trust Boundary Enforcement for Sidecar-less Microservice Security**

---

## Research Objectives

The primary objectives of this project are:

* Explore sidecar-less trust-boundary enforcement concepts for microservices.
* Investigate context-aware authorization using runtime telemetry.
* Compare traditional logs-only monitoring against contextual trust evaluation.
* Demonstrate how additional contextual signals can improve detection of unauthorized service interactions.
* Evaluate security effectiveness using standard classification metrics.

---

## Trust Evaluation Model

### Logs-Only Baseline

The baseline detector relies exclusively on application log content.

Examples:

* Unauthorized token reuse
* Replay attack indicators
* Invalid payload messages
* Unknown event sources

Detection decisions are made using keyword matching.

### CA-eBPF Framework

The proposed framework evaluates additional contextual attributes:

* Trust score
* Service identity validation
* Runtime anomaly indicators
* Trace-path consistency
* Invocation frequency analysis

These contextual signals are combined into a trust evaluation score used to classify communication events as benign or malicious.

---

## Experimental Dataset

The evaluation dataset consists of synthetic microservice communication events designed to emulate realistic cloud-native workloads.

### Dataset Composition

| Event Type            | Count |
| --------------------- | ----: |
| Benign Events         | 1,000 |
| Obvious Attack Events |   200 |
| Stealth Attack Events |   100 |
| Total Events          | 1,300 |

### Event Attributes

Each event contains:

* Service identifier
* Application log message
* Status information
* Trust score
* Service identity validation flag
* Runtime anomaly indicator
* Trace-path violation indicator
* Invocation frequency
* Ground-truth label

---

## Repository Structure

```text
ca-ebpf-evaluation/
│
├── generate_events.js
├── detect_logs.js
├── detect_caebpf.js
├── metrics.js
│
├── events.json
├── logs_results.json
├── caebpf_results.json
│
└── README.md
```

### File Descriptions

#### generate_events.js

Generates a synthetic dataset of benign and malicious microservice communication events.

#### detect_logs.js

Implements the logs-only baseline detector using application log analysis.

#### detect_caebpf.js

Implements the context-aware trust evaluation model using multiple telemetry attributes.

#### metrics.js

Computes evaluation metrics including:

* Accuracy
* Precision
* Recall
* F1-score

---

## Prerequisites

### Software Requirements

* Node.js 18+ (recommended)

Verify installation:

```bash
node --version
```

---

## Running the Evaluation

### Step 1: Generate Dataset

```bash
node generate_events.js
```

Expected output:

```text
Generated 1300 events
```

This creates:

```text
events.json
```

---

### Step 2: Run Logs-Only Baseline

```bash
node detect_logs.js
```

Generate metrics:

```bash
node metrics.js logs_results.json
```

---

### Step 3: Run CA-eBPF Detector

```bash
node detect_caebpf.js
```

Generate metrics:

```bash
node metrics.js caebpf_results.json
```

---

## Experimental Results

### Confusion Matrix Results

| Metric               | Logs-Only | CA-eBPF |
| -------------------- | --------: | ------: |
| True Positives (TP)  |       200 |     251 |
| False Positives (FP) |        39 |      10 |
| True Negatives (TN)  |       961 |     990 |
| False Negatives (FN) |       100 |      49 |

### Security Effectiveness Comparison

| Metric    | Logs-Only | CA-eBPF |
| --------- | --------: | ------: |
| Accuracy  |    89.31% |  95.46% |
| Precision |    83.68% |  96.17% |
| Recall    |    66.67% |  83.67% |
| F1-Score  |    74.21% |  89.48% |

---

## Key Findings

The evaluation demonstrates that contextual runtime telemetry can significantly improve trust-boundary enforcement effectiveness compared with traditional log-based monitoring.

Observed improvements include:

* Reduced false positives
* Improved malicious activity detection
* Better visibility into stealth attack scenarios
* Higher overall precision and recall
* Improved F1-score

The CA-eBPF framework achieved a **15.27 percentage-point improvement in F1-score** over the logs-only baseline.

---

## Limitations

This repository contains a prototype research implementation intended for experimental evaluation.

Current limitations include:

* Synthetic dataset generation
* Single-node simulation environment
* No direct kernel-level eBPF implementation
* No production Kubernetes deployment
* No latency or resource-consumption benchmarking

The implementation is intended to demonstrate trust-boundary enforcement concepts rather than serve as a production-ready security platform.

---

## Future Work

Potential future enhancements include:

* Real Kubernetes deployment
* Integration with eBPF telemetry frameworks
* Dynamic trust propagation across clusters
* Adaptive trust scoring
* Machine-learning-assisted anomaly detection
* Comparative evaluation against service mesh architectures

---

## Citation

If you use this repository in academic work, please cite:

```text
Kalaiah, U.
Context-Aware eBPF Trust Boundary Enforcement for Sidecar-less Microservice Security.
2026.
```

---

## License

This project is provided for research and educational purposes.
