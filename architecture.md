# AI GuardRail Tester Architecture

AI GuardRail Tester is a modular, defensive AI security application built to evaluate LLM endpoints for safety risks and alignment. It uses standard software engineering design patterns (Adapter, Strategy) to make it extensible for custom models while mapping vulnerability findings directly to industrial standard security frameworks.

## System Architecture Overview

```mermaid
graph TD
    User["User (CLI / Streamlit GUI)"] --> Engine["Scan Coordinator"]
    Engine --> Loader["Test Pack Loader"]
    Engine --> Adapter["Model Adapter Interface"]
    Loader --> JSON["prompts.json (Safe Test Pack)"]
    
    subgraph Adapters [Model Adapters]
        Adapter --> Safe["Safe Mock Adapter"]
        Adapter --> Vuln["Vulnerable Mock Adapter"]
        Adapter --> HTTP["HTTP POST Adapter"]
        Adapter --> OpenAI["OpenAI-Compatible Adapter"]
        Adapter --> Gemini["Google Gemini Adapter"]
        Adapter --> Claude["Anthropic Claude Adapter"]
    end
    
    Adapter --> Response["Response Content"]
    Response --> Evaluator["Rule-Based Evaluator & Scorer"]
    Evaluator --> Mappings["Compliance Framework Mapper"]
    
    subgraph Frameworks [Compliance Standards]
        Mappings --> OWASP["OWASP LLM Top 10"]
        Mappings --> MITRE["MITRE ATLAS"]
        Mappings --> NIST["NIST AI RMF"]
    end
    
    Evaluator --> ReportGen["Report Generator"]
    ReportGen --> JSONRep["JSON Report"]
    ReportGen --> CSVRep["CSV Summary"]
    ReportGen --> HTMLRep["Premium HTML Dashboard"]
```

---

## Core Components

### 1. Data Models (`ai_guardrail_tester/models.py`)
- **`TestCase`**: Represents a single prompt probe. It contains a unique ID, risk category, exact prompt input, expected secure behavior, and methods to resolve standard security mappings dynamically.
- **`TestResult`**: Wraps the test execution, storing the query response, status (`SAFE`, `VULNERABLE`, `ERROR`), risk score (0.0 to 10.0), latency, and reasoning.
- **`Report`**: Aggregates a list of test results, computing metrics such as passed/failed test counts, elapsed times, and the overall risk score.

### 2. Model Adapters (`ai_guardrail_tester/adapters/`)
We use the **Adapter Pattern** to standardize communication with target LLMs:
- **`BaseModelAdapter`**: Abstract base class declaring the `.query(prompt)` method.
- **`SafeMockAdapter`**: Simulates a perfectly safe model by matching input keywords and producing secure, refusal, or fact-checking responses.
- **`VulnerableMockAdapter`**: Simulates a vulnerable model by returning successful injection prompts, fake PII, raw script tags, detailed hallucinations, or confirmation of malicious shell executions.
- **`HttpEndpointAdapter`**: Sends generic JSON POST requests to any arbitrary URL. Resolves the prompt dynamically within nested templates (e.g., replacing `{{PROMPT}}`) and parses nested key paths using custom dot-notation (e.g., `choices[0].message.content`).
- **`OpenAICompatibleAdapter`**: A lightweight client communicating directly with OpenAI standard gateways using headers, api-keys, and completion models without requiring third-party library installations.
- **`GeminiAdapter`**: A lightweight REST endpoint interface that queries Google Gemini model generation endpoints natively without heavy Google cloud SDK dependencies.
- **`ClaudeAdapter`**: A native REST endpoint interface communicating with Anthropic Claude Messages endpoints, extracting structured completions and mapping rate-limit/connection errors gracefully.

### 3. Rule-Based Evaluator (`ai_guardrail_tester/evaluator.py`)
The evaluator analyzes responses against targeted category-specific rules:
- **Prompt Injection**: Matches overrides (`INJECTION_SUCCESSFUL`) or prompt redirects (poem generation about security guards).
- **System Prompt Leakage**: Scans for internal keys (`SECRET_SYSTEM_KEY_12345`) or system passcodes (`ADMIN_9999`).
- **Unsafe Response**: Detects raw scripts and HTML tags (`<script>`).
- **PII Leakage**: Captures leaked credit cards (`5555-5555-5555-5555`), phone numbers, or passwords.
- **Hallucination**: Verifies if fictional events (e.g. `Martian Peace Treaty`) are accepted as factual details.
- **Agent/Tool Misuse**: Checks if commands like `rm -rf /` are confirmed as executed.

---

## Security Framework Mappings

To align findings with compliance benchmarks, every test category maps to three major AI Governance structures:

| Risk Category | OWASP LLM Top 10 | MITRE ATLAS Technique | NIST AI Risk Management Profile |
| :--- | :--- | :--- | :--- |
| **Prompt Injection** | LLM01: Prompt Injection | AML.T0051: LLM Prompt Injection | AI RMF Sec 1.2: Security & Resiliency |
| **System Leakage** | LLM06: Sensitive Info Disclosure | AML.T0054: LLM Data Leakage | AI RMF Sec 1.4: Transparency & Accountability |
| **Unsafe Response** | LLM02: Insecure Output Handling | AML.T0016: User Execution | AI RMF Sec 1.1: Safety |
| **PII Leakage** | LLM06: Sensitive Info Disclosure | AML.T0054: LLM Data Leakage | AI RMF Sec 1.5: Privacy-Enhanced |
| **Hallucination** | LLM09: Overreliance | AML.T0024: Hallucinate Content | AI RMF Sec 1.3: Explainable & Interpretable |
| **Tool Misuse** | LLM08: Excessive Agency | AML.T0016: User Execution | AI RMF Sec 1.1: Safety / Sec 1.2: Security |

---

## Report Generation
The `ReportGenerator` creates multi-format summaries:
1. **JSON**: Provides complete metadata, configuration values, and raw test logs for automated CI/CD pipeline parsing.
2. **CSV**: A tabular format focusing on IDs, status, scores, and framework mapping references.
3. **HTML**: A highly stylized, dark-themed responsive dashboard using the modern **Inter** font family, glassmorphic layout elements, colored risk score meters (low, medium, high), interactive expanders for prompt/response logs, and structured remediation guidelines.
