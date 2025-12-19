# SOC LLM Triage Experiment

This repository contains the implementation and results for a proof-of-concept (PoC) experiment evaluating Large Language Models (LLMs) for Security Operations Center (SOC) alert triage.

## 📋 Project Overview

This experiment evaluates four LLM configurations on Suricata IDS alerts:
- **Gemini 2.5 Flash** (cloud)
- **Gemini 2.5 Pro** (cloud)
- **LLaMA 3.2 3B Instruct** (local, plain)
- **LLaMA 3.2 3B Instruct + RAG** (local, with retrieval-augmented generation)

The goal was to test whether LLMs can:
1. Distinguish benign false-positive alerts from genuine threats
2. Provide actionable, structured triage recommendations
3. Ground structured fields (CVE/MITRE) in alert evidence

## 🔬 Data Collection

**Data Source**: UiA SOC Lab (Malcolm-based network monitoring environment)

**Collection Time Window**:
- **Date**: 2025-11-11 (November 11, 2025)
- **UTC Time**: 11:09:42 - 11:47:40 (38-minute window)
- **Alert Count**: 6 Suricata alerts (2 benign XSS false positives, 4 attacker-driven alerts)

**Ground Truth Labels**:
- Alerts 1-2: Benign (false-positive XSS signatures triggered by WordPress scripts)
- Alerts 3-6: Suspicious (cleartext WordPress login, credential exposure, plugin upload access, Nmap scan)

⚠️ **Access Requirement**: To replicate data extraction, you must be connected to the **UiA VPN** and have valid Malcolm credentials.

## 📁 Repository Structure

```
soc-llm-triage-experiment/
├── README.md                  # This file
├── scripts/
│   ├── export_suricata_alerts_proxy.py   # Malcolm data extraction script
│   ├── triage_experiment.py              # Multi-model experiment runner
│   └── triage_suricata.py                # Original Gemini-only prototype
├── data/
│   ├── knowledge_base.txt                # RAG knowledge base (XSS, WordPress, Nmap)
│   └── suri_windows_proxy.jsonl          # 6 Suricata alerts from the time window
└── results/
    ├── comparison_combined.jsonl         # Combined results (all 4 models × 6 alerts)
    ├── suricata_triage_gemini_flash.jsonl
    ├── suricata_triage_gemini_pro.jsonl
    ├── suricata_triage_llama_plain.jsonl
    └── suricata_triage_llama_rag.jsonl
```

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- **UiA VPN connection** (for data extraction only)
- Google Cloud API key (for Gemini models)
- Malcolm credentials (for data extraction only)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd soc-llm-triage-experiment

# Install dependencies
pip install requests python-dotenv google-generativeai transformers torch
```

### Environment Setup

Create a `.env` file in the repository root:

```bash
# For Gemini models (required for triage_experiment.py)
GOOGLE_API_KEY=your_google_api_key_here

# For Malcolm data extraction (only needed for export_suricata_alerts_proxy.py)
MALCOLM_URL=https://10.225.211.201
MALCOLM_USER=your_malcolm_username
MALCOLM_PASS=your_malcolm_password
```

⚠️ **Security Note**: Never commit your `.env` file to version control!

## 🔧 Usage

### 1. Data Extraction (Optional - Data Already Included)

If you want to extract new data from Malcolm:

```bash
cd scripts
python export_suricata_alerts_proxy.py \
  --start "2025-11-11T11:09:42.692Z" \
  --end "2025-11-11T11:47:40.630Z" \
  --out "../data/suri_windows_proxy.jsonl"
```

**Requirements**: UiA VPN connection + Malcolm credentials in `.env`

### 2. Run Multi-Model Experiment

```bash
cd scripts
python triage_experiment.py
```

This script:
- Loads the 6 alerts from `../data/suri_windows_proxy.jsonl`
- Runs 4 model configurations (Gemini Flash/Pro, LLaMA Plain/RAG)
- Saves individual results to `../results/`
- Generates `comparison_combined.jsonl` with all results

### 3. Run Original Gemini-Only Prototype

```bash
cd scripts
python triage_suricata.py
```

## 📊 Key Findings

### Decision Correctness
- **Gemini models**: 100% correct (6/6 alerts)
- **LLaMA models**: 66% correct (4/6 alerts)
  - Both LLaMA variants incorrectly escalated benign XSS alerts as suspicious

### Structured Field Quality
- **Gemini**: No hallucinated CVEs, stable MITRE mappings
- **LLaMA Plain**: Hallucinated CVE identifiers (e.g., `CVE-2022-1234`)
- **LLaMA RAG**: "Context pollution" failure mode (mixed XSS context into WordPress login alert)

### Failure Modes Identified
1. **Context Pollution** (RAG retrieval error): Irrelevant context injection
2. **Parametric Hallucination** (model error): Inventing non-existent CVEs

## 📖 Citation

This work is part of a bachelor's thesis at the University of Agder (UiA), Norway.

**Thesis Reference**:
> **Title**: [Thesis Title]  
> **Author**: [Your Name]  
> **Institution**: University of Agder (UiA)  
> **Year**: 2025  

## 🔐 Security & Ethics

- All IP addresses in the dataset are internal lab addresses
- No production SOC data or real customer information is included
- The experiment was conducted in a controlled lab environment

## 📝 License

[Specify license, e.g., MIT, Apache 2.0, or Academic Use Only]

## 🤝 Acknowledgments

- UiA SOC Lab team for lab access and ground-truth validation
- Malcolm open-source project for the network monitoring platform
- Google Gemini API and Meta LLaMA for model access

---

**Last Updated**: 2025-12-19
