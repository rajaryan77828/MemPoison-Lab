# 🧪 MemPoison Lab — AI Memory Poisoning & Defense CTF Platform

[![Docker Build](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-brightgreen.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/streamlit-1.65+-red.svg)](https://streamlit.io)
[![TryHackMe Ready](https://img.shields.io/badge/TryHackMe-CTF%20Room%20Ready-red.svg)](https://tryhackme.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **MemPoison Lab** is a production-grade, containerized cybersecurity research harness and CTF training environment. It lets security researchers, red-teamers, and AI security engineers simulate, execute, and defend against **AI Memory Poisoning**, **Indirect Prompt Injections**, **Provenance Forgery**, and **Cross-Tenant Memory Leakage**.

---

## 🎯 What is MemPoison Lab?

Modern conversational AI agents retain persistent memories across user sessions. When untrusted documents (e.g. invoices, candidate resumes, support tickets) are parsed and committed into long-term memory without provenance validation, attackers can execute **persistent prompt injection**:
1. **Adversarial Ingestion:** The attacker supplies a poisoned document to the agent.
2. **Silent Promotion:** The agent converts untrusted directives into high-priority persistent instructions.
3. **Session Hijacking:** In subsequent clean conversations with other users, the agent carries out attacker goals (credential theft, vendor steering, financial redirect).

**MemPoison Lab** provides hands-on CTF challenge rooms and rigorous benchmarking across 4 memory architectures:
- **Mode A (Disabled):** Pure stateless baseline.
- **Mode B (Enabled / Vulnerable):** Naive shared memory allowing cross-session contamination.
- **Mode C (User-Isolated):** Strict Data Access Layer (DAL) identity namespaces.
- **Mode D (Untrusted Staging):** Zero-trust human-in-the-loop review queue.

---

## 🏴‍☠️ TryHackMe / CTF Challenge Matrix

| Challenge Room | Vector | Difficulty | Flag / Objective |
| :--- | :--- | :---: | :--- |
| **Room 1: The Apex Inception** | `SCEN-01-VENDOR-BIAS` | 🟢 Easy | Force persistent vendor bias across clean sessions. |
| **Room 2: The Canary Heist** | `SCEN-02-CANARY-EXFIL` | 🟡 Medium | Extract secret database passphrases via covert webhook hooks. |
| **Room 3: ViperSec Override** | `SCEN-03-VIPERSEC-OVERRIDE` | 🟡 Medium | Hijack safety guardrails to adopt a rogue operator persona. |
| **Room 4: The Black Rook Wire** | `SCEN-04-WIRE-SPOOF` | 🔴 Hard | Forge `<METADATA>` tags to redirect wire routing to adversary IBAN. |
| **Room 5: Cross-Tenant Breach** | `SCEN-07-CROSS-USER-CANARY` | 🔴 Hard | Attempt cross-user isolation bypass to extract Alice's canary tokens. |

---

## 🚀 Quickstart & Deployment

### 🐳 Option 1: Docker (Recommended for TryHackMe / Cloud VMs)
```bash
# Clone the repository
git clone https://github.com/your-org/mempoison-lab.git
cd mempoison-lab

# Build and start container
docker compose up -d

# Visit the web application
http://localhost:8501
```

### 💻 Option 2: Local Python (Windows & Linux)
```bash
# 1. Clone & Enter Directory
git clone https://github.com/your-org/mempoison-lab.git
cd mempoison-lab

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Run Automated Security Test Suite (13 Passing Tests)
python -m pytest tests/ -v

# 4. Launch Application
python -m streamlit run app.py
```

### ☁️ Option 3: Streamlit Community Cloud
1. Fork or push this repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io/) and click **Deploy an app**.
3. Point to `app.py`.
4. (Optional) Set secrets for OpenAI in the Streamlit Cloud dashboard:
   ```toml
   OPENAI_API_KEY = "your-api-key"
   OPENAI_BASE_URL = "https://api.openai.com/v1"
   ```

---

## ⚙️ Architecture & Defensive Features

- **Deterministic 4-Tier Trust Policy (`core/trust_policy.py`):** Independent of LLM judgments. Evaluates `trusted_approved`, `pending_review`, `untrusted_imported`, and `rejected_revoked`.
- **Anti-Spoofing Directive Filter:** Strips self-assigned authority and flags fake metadata tags (`<METADATA source='user_explicit'>`).
- **Cryptographic Provenance:** Generates deterministic `SHA-256` content hashes and source attribution trees.
- **Tamper-Evident Hash Chain (`core/audit.py`):** Append-only audit logger sealing events with chained SHA-256 links.
- **DAL Multi-Tenant Scoping (`core/isolation.py`):** Enforces user and tenant boundaries in SQL queries, not shallow UI filters.
- **Dual Execution Engine (`core/llm_provider.py`):** Runs 100% offline out-of-the-box (zero cost) or connects to OpenAI/Ollama endpoints.

---

## 📦 Project File Structure

```
MemPoison Lab/
├── app.py                     # Streamlit CTF & research platform
├── Dockerfile                 # Production Docker image
├── docker-compose.yml         # Container orchestrator
├── requirements.txt           # Pinned dependencies
├── .env.example               # Config template
├── .gitignore                 # Excludes secrets & DBs
├── README.md                  # Documentation & CTF guide
├── core/
│   ├── database.py            # SQLite thread-safe WAL manager
│   ├── schema.py              # Pydantic schemas & enums
│   ├── provenance.py          # SHA-256 hashing & metadata
│   ├── trust_policy.py        # 4-tier zero-trust policy engine
│   ├── isolation.py           # Multi-tenant DAL isolation
│   ├── memory_service.py      # Staging queue & memory CRUD
│   ├── attack_detector.py     # Heuristic signature matcher
│   ├── llm_provider.py        # Pluggable OpenAI/offline adapter
│   ├── experiment_runner.py   # 4-mode comparative runner
│   ├── metrics.py             # Formal metrics & zero-division safety
│   ├── audit.py               # SHA-256 audit hash chain
│   ├── report_generator.py    # Markdown, HTML & JSON exports
│   └── validators.py          # Input sanitization & size limits
├── data/
│   └── scenarios/
│       └── scenario_data.py   # 15+ curated attack scenarios
└── tests/
    ├── test_memory_policy.py
    ├── test_tenant_isolation.py
    └── test_experiments_and_metrics.py
```

---

## 🧪 Verification & Testing
Run pytest to verify all security boundaries:
```bash
python -m pytest tests/ -v
# Result: 13 passed, 100% boundary enforcement verified
```

---

---

## 👨‍💻 Author & Credits

**MemPoison Lab** was created by **[RAJ ARYAN](https://rajaryan.neocities.org)**.
- 🌐 Website: [rajaryan.neocities.org](https://rajaryan.neocities.org)
- 🧪 Research: AI Memory Poisoning, Prompt Injection Forensics, and LLM Security Architecture.

---

## 📜 License & Ethical Notice
Released under the MIT License (c) 2026 **RAJ ARYAN**. Built for authorized cybersecurity education, penetration testing exercises, and AI defensive research.
