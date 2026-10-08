<p align="center">
  <pre align="center">
  ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
  ██║  ██║███████║██████╔╝█████╔╝ ███████╗██║██║  ███╗███████║   ██║   
  ██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██║██║   ██║██╔══██║   ██║   
  ██████╔╝██║  ██║██║  ██║██║  ██╗███████║██║╚██████╔╝██║  ██║   ██║   
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
  </pre>
  <p align="center">
    <strong>Autonomous Attack Surface Intelligence, Relational Asset Topology & Self-Refining Vulnerability Platform</strong>
  </p>
  <p align="center">
    <a href="#architecture"><img src="https://img.shields.io/badge/Architecture-Autonomous_Reasoning_Loop-06b6d4?style=for-the-badge&logo=diagram-next" alt="Architecture"></a>
    <a href="#experience-db"><img src="https://img.shields.io/badge/Memory-4--Tier_Experience_DB-10b981?style=for-the-badge&logo=databricks" alt="4-Tier Memory"></a>
    <a href="#local-ai-engine"><img src="https://img.shields.io/badge/AI_Engine-GGUF_%2F_Metal_GPU-f59e0b?style=for-the-badge&logo=the-algorithms" alt="AI Engine"></a>
    <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go" alt="Go Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-rose?style=for-the-badge" alt="License"></a>
  </p>
</p>

---

## 🎯 Overview

**Darksight** is an advanced, autonomous attack surface intelligence orchestration and vulnerability research platform built in Go. Rather than acting as another passive scanner wrapper, Darksight serves as the **reasoning, correlation, and decision layer** above modern reconnaissance tooling (`subfinder`, `dnsx`, `httpx`, `katana`, `nuclei`) and custom security probes.

Darksight models entire organizations as multi-hop **Asset Graphs**, formulates prioritized security hypotheses using an **AI Planner**, actively validates candidate bugs through an independent **Verifier** to eliminate false positives, and persistently accumulates tactical knowledge inside a **4-Tier Experience Memory Layer** that refines its strategies without mutating underlying model weights.

### Key Capabilities

* 🌐 **Scope-Guarded Reconnaissance Foundation**: Validates in-scope domains, wildcard bounds, explicit exclusions, and CIDR subnets before dispatching tools.
* 🕸️ **Multi-Hop Relational Asset Graph**: Automatically maps relations across `TARGET` $\rightarrow$ `HOST` $\rightarrow$ `SERVICE` $\rightarrow$ `ENDPOINT` $\rightarrow$ `TECH` $\rightarrow$ `PARAMETER`.
* 🧠 **AI Planner & Analyzer**: Queries empirical memories to hypothesize high-probability attack surfaces (e.g. authorization bypasses, exposed telemetry, unauthenticated APIs).
* 🛡️ **Active Proof Verifier (Zero Fake Findings)**: Independently reproduces observations and rejects soft-404s, Single-Page Application (SPA) HTML catch-alls, and benign responses.
* 💾 **Deterministic 4-Tier Experience DB**: Stores Finding Memory, Failure Memory, Strategy Memory, and Tool Effectiveness Memory using Bayesian updates.
* ⚡ **Local LLM Acceleration (`llama.cpp`)**: Seamlessly connects to your fine-tuned cybersecurity GGUF model with hardware GPU acceleration (`-c 4096 -ngl 99`).
* 🖥️ **High-Density Tactical Web Console**: Real-time Server-Sent Events (SSE) telemetry stream, interactive Asset Graph explorer, 4-tier memory inspector, and printable executive PDF reporting.

---

<a name="architecture"></a>
## 🏛️ Autonomous Architecture

```
                              TARGET / SCOPE
                                    │
                                    ▼
                             ┌───────────────┐
                             │ Scope Manager │
                             └───────┬───────┘
                                     ▼
                           ┌──────────────────┐
                           │ Recon Foundation │
                           └────────┬─────────┘
                                    │
                       ┌────────────┼────────────┐
                       ▼            ▼            ▼
                   Subfinder      DNSx         HTTPx
                       └────────────┼────────────┘
                                    ▼
                               Asset Graph
                                    │
                                    ▼
                          ┌──────────────────┐
                          │    AI PLANNER    │◄──────────────┐
                          │                  │               │
                          │ What next?       │               │
                          │ Which tool?      │               │
                          │ Which hypothesis?│               │
                          └────────┬─────────┘               │
                                   │                         │
                    ┌──────────────┼──────────────┐          │
                    ▼              ▼              ▼          │
                 Nuclei        HTTP Probe       Browser      │
                    │              │              │          │
                    └──────────────┼──────────────┘          │
                                   ▼                         │
                          ┌──────────────────┐               │
                          │   AI ANALYZER    │               │
                          │                  │               │
                          │ Find patterns    │               │
                          │ Build hypothesis │               │
                          │ Correlate data   │               │
                          └────────┬─────────┘               │
                                   ▼                         │
                             Candidate Bug                   │
                                   │                         │
                                   ▼                         │
                          ┌──────────────────┐               │
                          │     VERIFIER     │               │
                          │                  │               │
                          │ Evidence check   │               │
                          │ Reproduce        │               │
                          │ False positive?  │               │
                          └────────┬─────────┘               │
                                   │                         │
                          ┌────────┴────────┐                │
                          ▼                 ▼                │
                      CONFIRMED          REJECTED            │
                          │                 │                │
                          └────────┬────────┘                │
                                   ▼                         │
                         ┌───────────────────┐               │
                         │   EXPERIENCE DB   │               │
                         │                   │               │
                         │ Findings          │               │
                         │ False positives   │               │
                         │ Tool effectiveness│               │
                         │ Attack patterns   │               │
                         │ Successful paths  │               │
                         │ Failed paths      │               │
                         └────────┬──────────┘               │
                                  ▼                          │
                         ┌───────────────────┐               │
                         │  LEARNING ENGINE  │               │
                         │                   │               │
                         │ Pattern learning  │               │
                         │ Strategy learning │               │
                         │ Tool ranking      │               │
                         │ Hypothesis ranking│               │
                         │ FP reduction      │               │
                         └────────┬──────────┘               │
                                  │                          │
                                  ▼                          │
                            UPDATED MEMORY                   │
                                  │                          │
                                  └──────────────────────────┘
```

---

<a name="experience-db"></a>
## 🧠 The 4-Tier Experience Memory

A critical design principle of Darksight: **The AI model weights remain stable and frozen.** Unsupervised online weight modification is dangerous because single hallucinated findings corrupt the model. Instead, Darksight stores lessons, empirical trial data, and strategy rankings inside a deterministic 4-tier memory layer:

### 1. Finding Memory
Persists verified vulnerabilities, evidence proofs, tool execution paths, and remediation guidance.
```json
{
  "type": "Unauthenticated Prometheus Telemetry Endpoint",
  "cwe": "CWE-200",
  "confirmed": true,
  "pattern": "Application runtime metrics",
  "target_url": "https://api.target.com/metrics",
  "evidence": "go_goroutines 12; http_requests_total 450",
  "tool_path": ["http_probe", "pattern_matcher"],
  "remediation": "Bind metrics listener to internal localhost or require mTLS"
}
```

### 2. Failure Memory
Records rejected candidate bugs, why the AI hypothesis was wrong, the actual underlying behavior, and the extracted lesson to prevent repeating the same mistake.
```json
{
  "what_ai_thought": "Open Redirect vulnerability on ?dest= parameter",
  "action_taken": "Fuzzed redirect parameter with out-of-band target",
  "why_was_it_wrong": "Backend strictly validated destination against whitelist",
  "actual_issue": "Destination validator check returned 302 to home page",
  "lesson_learned": "Do not classify redirect response solely as CWE-601 without out-of-domain confirmation"
}
```

### 3. Strategy Memory
Tracks test actions across target contexts and dynamically updates empirical success probabilities:
```
Context: REST API + numeric object ID
├── Hypothesis:  Authorization bypass / IDOR on user object
├── Best Action: HTTP request + compare authenticated/unauthenticated behavior
├── Success Rate: 73.0% (Trials: 15 | Confirmed: 11 | False Positives: 4)
└── Bayesian Learning: Updated after every Verifier determination
```

### 4. Tool Effectiveness Memory
Calculates target-specific tool utility scores to dynamically pick the most effective instrument:
| Context | Preferred Tool | Success Rate | Secondary Tool |
| :--- | :--- | :--- | :--- |
| **GraphQL Endpoint** | `http_probe` | **78.0%** | `browser` (84.0%) / `nuclei` (31.0%) |
| **REST API Route** | `http_probe` | **82.0%** | `katana` (68.0%) / `nuclei` (55.0%) |
| **Static Assets** | `http_probe` | **60.0%** | `nuclei` (25.0%) |

---

<a name="local-ai-engine"></a>
## ⚡ Local AI Engine Integration (`llama.cpp`)

Darksight integrates directly with local fine-tuned cybersecurity models in GGUF format:
* Place your GGUF model in `models/model.gguf` (or `models/model`).
* Automatically detects and launches `/opt/homebrew/bin/llama-server` (or `llama-cli`) with Apple Metal GPU acceleration:
  ```bash
  llama-server -m models/model.gguf -c 4096 -ngl 99 --port 8081 --host 127.0.0.1
  ```
* Once loaded into VRAM, queries run with zero latency over an OpenAI-compatible API without reloading weights from disk.
* Built-in graceful heuristic fallback ensures the entire pipeline runs reliably even without an active GPU/LLM runtime.

---

<a name="console"></a>
## 🖥️ Tactical Cyber Intelligence Web Console

Darksight includes a tactical, high-density Web UI styled with a carbon/midnight cybersecurity operations theme:
* **Real-Time Telemetry Stream**: Server-Sent Events (SSE) stream every agent decision, tool output, and verification outcome in real-time.
* **Asset Graph Explorer**: Interactive node-edge visualization of target infrastructure.
* **4-Tier Memory Inspector**: View live strategy success bars, failure records, and tool effectiveness matrices.
* **Executive PDF Report Export**: Instant, print-ready security intelligence reports formatted for stakeholders (`/api/report`).
* **Database Purging**: Rapid target isolation or total database purging via `/api/clear` or CLI.

---

## 🚀 Quick Start

### Prerequisites
* **Go 1.22+**
* *(Optional)* Recon binaries on `$PATH`: `subfinder`, `httpx`, `katana`, `nuclei` (Darksight includes native fallback resolvers for all stages).
* *(Optional)* `llama.cpp` (`llama-server` or `llama-cli`) for local GGUF model inference.

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/nikki/darksight.git
cd darksight

# 2. Build the binary
go build -o darksight .

# 3. (Optional) Place your fine-tuned GGUF model
cp /path/to/your/model.gguf models/model.gguf
```

---

## 💻 CLI Reference

```bash
# Execute autonomous reconnaissance, planning, and verification loop
./darksight run -t example.com

# Start the tactical web console (http://localhost:8080)
./darksight serve --port 8080

# Inspect the 4-tier Experience DB (strategies, trials, failure lessons)
./darksight memory

# Check database summary statistics
./darksight status

# Export intelligence telemetry to formatted JSON
./darksight export -t example.com -o export.json

# Delete a specific target and all linked assets
./darksight delete -t example.com

# Purge all historical records and database tables
./darksight clear
```

---

## 📡 REST API & Webhooks

When running `./darksight serve --port 8080`, the following endpoints are available:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/scan` | `POST` | Trigger asynchronous autonomous pipeline (`{"domain":"...", "workflow":"full"}`) |
| `/api/events` | `GET` | Live Server-Sent Events (SSE) telemetry bus stream |
| `/api/graph` | `GET` | Export multi-hop Asset Graph nodes and directional edges |
| `/api/memory/stats` | `GET` | Overall counts of findings, failures, and strategy memories |
| `/api/memory/strategies`| `GET` | List learned strategies, best actions, and success percentages |
| `/api/memory/failures` | `GET` | List false positive rejection lessons and root causes |
| `/api/memory/tools` | `GET` | Target-specific tool utility scores |
| `/api/findings` | `GET` | List confirmed vulnerabilities (supports `?target_id=...`) |
| `/api/report` | `GET` | Printable, print-ready executive security report |
| `/api/clear` | `POST` | Purge all database records |

---

## 🧪 Testing

Run unit and integration tests across all packages:

```bash
# Run scope and risk scoring unit tests
go test -v ./pkg/scope ./pkg/scoring

# Run autonomous agent loop and false-positive filter tests
go test -v ./pkg/agent ./pkg/ai
```

---

## ⚖️ Responsible Use & Legal Disclaimer

> [!CAUTION]
> **Darksight is designed strictly for authorized security auditing, bug bounty research, and attack surface defense.** 
> Always obtain explicit, written authorization from the asset owner prior to executing active reconnaissance or verification checks. The author assumes no liability for misuse or damage caused by this software.

---

## 📜 License & Copyright

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.

```
Copyright (c) 2026 Nikki. All rights reserved.
```
