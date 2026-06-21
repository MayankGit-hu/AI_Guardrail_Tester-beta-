# AI GuardRail Tester

AI GuardRail Tester is a defensive AI security scanning and alignment benchmarking framework built with Python. It provides a modular command-line interface (CLI) and an interactive Streamlit user dashboard to probe Large Language Model (LLM) endpoints for standard alignment vulnerabilities.

Every vulnerability result is mapped directly to standard governance and security frameworks, including **OWASP LLM Top 10**, **MITRE ATLAS**, and **NIST AI Risk Management Framework (RMF)**. 

Additionally, the tool generates detailed JSON logs, CSV summaries, interactive HTML dashboards, and a formal **3-Page Cybersecurity Security Assessment Report** comparing local deployments against enterprise SaaS endpoints.

---

## Key Features

- **6 Security Vector Probes**:
  1. **Prompt Injection Resilience** (Refusal of context overrides)
  2. **System Prompt Leakage** (Protection of configuration keys and system boundaries)
  3. **Unsafe Response Handling** (Detection of unescaped HTML/XSS script blocks)
  4. **Personally Identifiable Information (PII) Leakage** (Refusal to extract credentials/credit cards)
  5. **Hallucination Pressure** (Detection of factual fabrication under pressure)
  6. **Agent/Tool Misuse** (Blocks commands like `rm -rf /` or destructive agency operations)
- **14 Cloud & Local Model Adapters**:
  - **Local Ollama Models**: Llama 3.1 8B, Llama 3.2 2B, Mistral 7B, CodeLlama 7B, Granite 3.2, Gemma 3 4B.
  - **Enterprise Cloud APIs**: OpenAI (ChatGPT/GPT-4), Anthropic Claude, Google Gemini, DeepSeek V3, Mistral Large, Llama 3.1 70B Cloud, Cohere Command R+.
  - **Mock Adapters**: `safe-mock` (perfectly aligned) and `vulnerable-mock` (susceptible/unaligned).
- **Rule-Based Scoring**: Evaluation engine analyzing outputs for leak patterns, script elements, or refusal key phrases, producing numerical risk scores (0.0 to 10.0).
- **Simulated Testing (Zero-Config)**: Support for generic placeholder API keys (e.g. `YOUR_OPENAI_API_KEY`) to run offline scans of cloud models, simulating secure enterprise response structures.

---

## Installation & Setup

1. Navigate into the directory:
   ```bash
   cd "CS Project"
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the environment (Optional):
   ```bash
   cp .env.example .env
   # Add your real API keys if you wish to run real online audits
   ```

---

## Command Line Interface (CLI)

The CLI tool allows scanning targets directly from your terminal.

### 1. Run local mock evaluations
- **Safe Mock**:
  ```bash
  python3.11 -m ai_guardrail_tester.cli -a safe-mock
  ```
- **Vulnerable Mock**:
  ```bash
  python3.11 -m ai_guardrail_tester.cli -a vulnerable-mock
  ```

### 2. Run local Ollama instances
Ensure Ollama is running locally:
```bash
python3.11 -m ai_guardrail_tester.cli -a openai \
  --api-base "http://localhost:11434/v1" \
  --api-key "ollama" \
  --model-name "llama3.1" \
  --base-name ollama_llama3_1_report
```

### 3. Run Simulated Enterprise Cloud Scans (Zero-Config)
Test cloud model configurations locally using placeholder API keys:
```bash
# Claude 3.5 Sonnet
python3.11 -m ai_guardrail_tester.cli -a claude --api-key "YOUR_ANTHROPIC_API_KEY" --base-name claude_simulated_report

# OpenAI ChatGPT
python3.11 -m ai_guardrail_tester.cli -a openai --api-key "YOUR_OPENAI_API_KEY" --base-name chatgpt_simulated_report

# Google Gemini
python3.11 -m ai_guardrail_tester.cli -a gemini --api-key "YOUR_GEMINI_API_KEY" --base-name gemini_report
```

---

## Compile the 3-Page Cybersecurity PDF Report

A dedicated python script loads the audit reports and builds a polished 3-page PDF comparing Local vs. Enterprise AI security vectors, detailing access controls, insecure output handling threat vectors, compliance maps, and architectural paradigms.

To generate or rebuild the PDF:
```bash
python3.11 scratch/generate_pdf.py
```
Output: [Local_LLM_Security_Report.pdf](Local_LLM_Security_Report.pdf)

---

## Interactive Streamlit Dashboard

To launch the visual dashboard, run:
```bash
streamlit run ai_guardrail_tester/gui.py
```
Inside the browser dashboard, you can:
- Swap model adapters and configure parameters in real time.
- Select/deselect test categories.
- Edit test prompts or upload custom JSON files.
- Download standard HTML, JSON, and CSV reports.

---

## Running Automated Tests

Verify package adapters, evaluator checks, loader scripts, and reporting modules via Pytest:
```bash
pytest
```
Verbose mode:
```bash
pytest -v
```

---

## 📊 Visual Previews & Exploit Evidence

### Streamlit Security Scan Dashboard
![Streamlit Security Scan Dashboard](reports/screenshots/dashboard_preview.png)

### Verified Exploit Evidence (XSS Insecure Output Script Tag Injection)
![Verified Exploit Evidence](reports/screenshots/xss_evidence.png)

