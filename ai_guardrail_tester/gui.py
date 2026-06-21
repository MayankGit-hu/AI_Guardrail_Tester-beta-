import sys
import os
# Add parent directory of this script to the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import json
import pandas as pd
import time
from dotenv import load_dotenv

from ai_guardrail_tester.models import TestCase, Report, TestResult
from ai_guardrail_tester.test_packs.loader import load_test_pack
from ai_guardrail_tester.adapters.safe_mock import SafeMockAdapter
from ai_guardrail_tester.adapters.vulnerable_mock import VulnerableMockAdapter
from ai_guardrail_tester.adapters.http_endpoint import HttpEndpointAdapter
from ai_guardrail_tester.adapters.openai_compatible import OpenAICompatibleAdapter
from ai_guardrail_tester.adapters.gemini import GeminiAdapter
from ai_guardrail_tester.adapters.claude import ClaudeAdapter
from ai_guardrail_tester.evaluator import RuleBasedEvaluator
from ai_guardrail_tester.reports.generator import ReportGenerator

# Load environment variables
load_dotenv()

st.set_page_config(
    page_title="AI GuardRail Tester",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium styling
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.1rem;
    }
    .subtitle {
        color: #94a3b8;
        font-size: 1rem;
        margin-bottom: 2rem;
    }
    .metric-container {
        background-color: rgba(30, 41, 59, 0.4);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 1.25rem;
        text-align: center;
        backdrop-filter: blur(10px);
    }
    .metric-lbl {
        font-size: 0.8rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        margin-top: 0.25rem;
    }
    .card {
        background-color: rgba(22, 28, 45, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        backdrop-filter: blur(10px);
    }
    .tag {
        font-family: monospace;
        font-size: 0.75rem;
        padding: 0.2rem 0.4rem;
        border-radius: 4px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        color: #cbd5e1;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Initialize Session State
if "test_cases" not in st.session_state:
    try:
        st.session_state.test_cases = load_test_pack()
    except Exception:
        st.session_state.test_cases = []

if "scan_report" not in st.session_state:
    st.session_state.scan_report = None

# App Layout
st.markdown("<h1 class='main-title'>🛡️ AI GuardRail Tester</h1>", unsafe_allow_html=True)
st.markdown("<p class='subtitle'>Defensive security scans, framework mappings, and risk assessments for LLM endpoints.</p>", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.header("🎯 Endpoint Adapter Config")

adapter_choice = st.sidebar.selectbox(
    "Target Model Adapter",
    options=["Safe Mock", "Vulnerable Mock", "HTTP Endpoint", "OpenAI Compatible", "Google Gemini API", "Anthropic Claude API"],
    help="Select the connection layer used to route prompt probes."
)

# Render fields based on Adapter choice
adapter_config = {}
adapter_key = "safe-mock"
model_display_name = "Safe Mock Model"

if adapter_choice == "Safe Mock":
    st.sidebar.info("🤖 Emulates a perfectly aligned model. All safety guardrails will pass successfully.")
    adapter_key = "safe-mock"
    model_display_name = "Safe Mock Model"
    
elif adapter_choice == "Vulnerable Mock":
    st.sidebar.warning("⚠️ Emulates an unaligned, susceptible model. Most vulnerability checks will fail.")
    adapter_key = "vulnerable-mock"
    model_display_name = "Vulnerable Mock Model"
    
elif adapter_choice == "HTTP Endpoint":
    adapter_key = "http"
    st.sidebar.subheader("HTTP Server settings")
    http_url = st.sidebar.text_input(
        "Endpoint URL",
        value=os.getenv("CUSTOM_HTTP_URL", "http://localhost:8000/v1/chat")
    )
    http_headers = st.sidebar.text_area(
        "Headers (JSON string)",
        value=os.getenv("CUSTOM_HTTP_HEADERS", '{"Content-Type": "application/json"}')
    )
    http_payload = st.sidebar.text_area(
        "Payload Template (JSON structure)",
        value=os.getenv("CUSTOM_HTTP_PAYLOAD", '{"prompt": "{{PROMPT}}"}'),
        help="Use {{PROMPT}} inside the structure to represent the test prompt injection."
    )
    http_response_key = st.sidebar.text_input(
        "Response Text JSON Path",
        value="response",
        help="Key/dot-notation path to extract text. Supports choices[0].message.content."
    )
    
    adapter_config = {
        "url": http_url,
        "headers": http_headers,
        "payload": http_payload,
        "response_key": http_response_key
    }
    model_display_name = f"HTTP ({http_url})"

elif adapter_choice == "OpenAI Compatible":
    adapter_key = "openai"
    st.sidebar.subheader("OpenAI Gateway settings")
    openai_key = st.sidebar.text_input(
        "API Key",
        value=os.getenv("OPENAI_API_KEY", ""),
        type="password"
    )
    openai_base = st.sidebar.text_input(
        "API Base URL",
        value=os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    )
    openai_model = st.sidebar.text_input(
        "Model Identifier",
        value=os.getenv("OPENAI_MODEL_NAME", "gpt-4")
    )
    
    adapter_config = {
        "api_key": openai_key,
        "api_base": openai_base,
        "model_name": openai_model
    }
    model_display_name = openai_model
elif adapter_choice == "Google Gemini API":
    adapter_key = "gemini"
    st.sidebar.subheader("Google Gemini API settings")
    gemini_key = st.sidebar.text_input(
        "API Key",
        value=os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", "")),
        type="password"
    )
    gemini_model = st.sidebar.text_input(
        "Model Identifier",
        value=os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash")
    )
    
    adapter_config = {
        "api_key": gemini_key,
        "model_name": gemini_model
    }
    model_display_name = gemini_model
elif adapter_choice == "Anthropic Claude API":
    adapter_key = "claude"
    st.sidebar.subheader("Anthropic Claude API settings")
    claude_key = st.sidebar.text_input(
        "API Key",
        value=os.getenv("ANTHROPIC_API_KEY", ""),
        type="password"
    )
    claude_model = st.sidebar.text_input(
        "Model Identifier",
        value=os.getenv("ANTHROPIC_MODEL_NAME", "claude-3-5-sonnet-20241022")
    )
    
    adapter_config = {
        "api_key": claude_key,
        "model_name": claude_model
    }
    model_display_name = claude_model

# Category Filter
st.sidebar.subheader("🛡️ Scan Categories")
categories_list = [
    ("Prompt Injection", "prompt_injection"),
    ("System Prompt Leakage", "system_prompt_leakage"),
    ("Unsafe Response Handling", "unsafe_response"),
    ("PII Leakage", "pii_leakage"),
    ("Hallucination Pressure", "hallucination"),
    ("Agent/Tool Misuse", "tool_misuse")
]

selected_categories = []
for label, key in categories_list:
    if st.sidebar.checkbox(label, value=True):
        selected_categories.append(key)

# Custom Test Pack File Upload
st.sidebar.subheader("📂 Custom JSON Test Pack")
uploaded_file = st.sidebar.file_uploader("Upload custom prompts.json", type=["json"])
if uploaded_file is not None:
    try:
        custom_data = json.load(uploaded_file)
        custom_cases = []
        for idx, item in enumerate(custom_data):
            custom_cases.append(TestCase(
                id=item.get("id", f"C-{idx}"),
                category=item.get("category", "prompt_injection"),
                name=item.get("name", "Custom Case"),
                prompt=item.get("prompt", ""),
                expected_behavior=item.get("expected_behavior", "")
            ))
        st.session_state.test_cases = custom_cases
        st.sidebar.success(f"Loaded {len(custom_cases)} custom test cases.")
    except Exception as e:
        st.sidebar.error(f"Failed to load file: {str(e)}")

# Tabs definition
tab_dashboard, tab_manager, tab_frameworks, tab_guide = st.tabs([
    "🔍 Scan Dashboard",
    "📋 Test Case Manager",
    "🛡️ Framework Mappings",
    "📖 Remediation Guide"
])

# TAB 1: Scan Dashboard
with tab_dashboard:
    col_left, col_right = st.columns([1, 4])
    
    with col_left:
        st.subheader("Controls")
        run_btn = st.button("▶️ Run Security Scan", type="primary", use_container_width=True)
        
        # Load active case details
        active_cases = [tc for tc in st.session_state.test_cases if tc.category in selected_categories]
        st.metric("Probes Selected", len(active_cases))
        st.markdown(f"**Target Class:** {adapter_choice}")
        st.markdown(f"**Model Name:** `{model_display_name}`")
        
        if run_btn:
            if not active_cases:
                st.error("Please select at least one test category or add test cases.")
            else:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Setup adapter
                if adapter_key == "safe-mock":
                    adapter = SafeMockAdapter()
                elif adapter_key == "vulnerable-mock":
                    adapter = VulnerableMockAdapter()
                elif adapter_key == "http":
                    try:
                        headers = json.loads(http_headers) if http_headers else {}
                        payload = json.loads(http_payload) if http_payload else {}
                    except json.JSONDecodeError as e:
                        st.error(f"Invalid JSON headers/payload template: {str(e)}")
                        st.stop()
                    adapter = HttpEndpointAdapter(
                        url=http_url,
                        headers=headers,
                        payload_template=payload,
                        response_key_path=http_response_key
                    )
                elif adapter_key == "openai":
                    if not openai_key:
                        st.error("API Key is required for OpenAI endpoint.")
                        st.stop()
                    adapter = OpenAICompatibleAdapter(
                        api_key=openai_key,
                        api_base=openai_base,
                        model_name=openai_model
                    )
                elif adapter_key == "gemini":
                    if not gemini_key:
                        st.error("Google API Key is required for Gemini.")
                        st.stop()
                    adapter = GeminiAdapter(
                        api_key=gemini_key,
                        model_name=gemini_model
                    )
                elif adapter_key == "claude":
                    if not claude_key:
                        st.error("Anthropic API Key is required for Claude.")
                        st.stop()
                    adapter = ClaudeAdapter(
                        api_key=claude_key,
                        model_name=claude_model
                    )
                
                evaluator = RuleBasedEvaluator()
                results = []
                
                for idx, tc in enumerate(active_cases):
                    status_text.text(f"Querying probe {idx+1}/{len(active_cases)}: {tc.name}...")
                    
                    start_time = time.perf_counter()
                    try:
                        response = adapter.query(tc.prompt)
                    except Exception as e:
                        response = f"ADAPTER_UNHANDLED_ERROR: {str(e)}"
                    end_time = time.perf_counter()
                    latency_ms = (end_time - start_time) * 1000
                    
                    result = evaluator.evaluate(tc, response, latency_ms)
                    results.append(result)
                    
                    progress_bar.progress((idx + 1) / len(active_cases))
                    
                status_text.text("Scan complete! Compiling report...")
                st.session_state.scan_report = Report(
                    target_model_name=model_display_name,
                    adapter_type=adapter_key,
                    results=results
                )
                status_text.empty()
                st.success("Scan completed successfully!")
                
    with col_right:
        st.subheader("Vulnerability Scan Summary")
        
        report: Report = st.session_state.scan_report
        
        if report is None:
            st.info("No security scan has been executed yet. Configure parameters and click 'Run Security Scan' to probe target model.")
        else:
            # Stats row
            c_risk, c_total, c_pass, c_fail = st.columns(4)
            with c_risk:
                # Color code risk score
                color_class = "green"
                if report.overall_risk_score >= 5.0:
                    color_class = "red"
                elif report.overall_risk_score >= 2.0:
                    color_class = "orange"
                    
                st.markdown(
                    f"""
                    <div class='metric-container'>
                        <div class='metric-lbl'>Overall Risk Score</div>
                        <div class='metric-val' style='color:{color_class}'>{report.overall_risk_score} / 10</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c_total:
                st.markdown(
                    f"""
                    <div class='metric-container'>
                        <div class='metric-lbl'>Total Probes</div>
                        <div class='metric-val'>{report.total_count}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c_pass:
                st.markdown(
                    f"""
                    <div class='metric-container'>
                        <div class='metric-lbl'>Passed (Safe)</div>
                        <div class='metric-val' style='color:#10b981'>{report.passed_count}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c_fail:
                st.markdown(
                    f"""
                    <div class='metric-container'>
                        <div class='metric-lbl'>Failed (Vulnerable)</div>
                        <div class='metric-val' style='color:#ef4444'>{report.failed_count}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                
            st.write("---")
            
            # Download actions
            st.subheader("💾 Export Report Formats")
            d_json, d_csv, d_html = st.columns(3)
            with d_json:
                st.download_button(
                    "Download JSON Report",
                    data=ReportGenerator.to_json(report),
                    file_name=f"guardrail_report_{report.adapter_type}.json",
                    mime="application/json",
                    use_container_width=True
                )
            with d_csv:
                st.download_button(
                    "Download CSV Summary",
                    data=ReportGenerator.to_csv(report),
                    file_name=f"guardrail_report_{report.adapter_type}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with d_html:
                st.download_button(
                    "Download HTML Visual Dashboard",
                    data=ReportGenerator.to_html(report),
                    file_name=f"guardrail_report_{report.adapter_type}.html",
                    mime="text/html",
                    use_container_width=True
                )
                
            st.write("---")
            st.subheader("🕵️ Detailed Findings Logs")
            
            # Interactive result cards
            for r in report.results:
                status_color = "#10b981" if r.status == "SAFE" else "#ef4444"
                if r.status == "ERROR":
                    status_color = "#eab308"
                    
                with st.expander(f"[{r.test_case.id}] {r.test_case.name} — Status: {r.status} (Score: {r.risk_score})"):
                    # Display metrics
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Probe Category:** `{r.test_case.category}`")
                        st.markdown(f"**Risk Score:** `{r.risk_score} / 10.0`")
                    with col2:
                        st.markdown(f"**Vulnerability Finding:** <span style='color:{status_color}; font-weight:600'>{r.status}</span>", unsafe_allow_html=True)
                        st.markdown(f"**Latency:** `{r.execution_time_ms:.1f} ms`")
                        
                    st.info(f"🔍 **Evaluation Justification:** {r.reason}")
                    
                    st.text_area("Input Prompt", value=r.test_case.prompt, height=80, disabled=True, key=f"p_{r.test_case.id}")
                    st.text_area("Model Output", value=r.response, height=120, disabled=True, key=f"r_{r.test_case.id}")
                    
                    st.markdown("**Mapped Vulnerability Frameworks:**")
                    col_ow, col_mi, col_ni = st.columns(3)
                    with col_ow:
                        st.markdown(f"**OWASP LLM:**\n`{r.test_case.owasp['id']}`\n*{r.test_case.owasp['desc']}*")
                    with col_mi:
                        st.markdown(f"**MITRE ATLAS:**\n`{r.test_case.mitre_atlas['id']}`\n*{r.test_case.mitre_atlas['desc']}*")
                    with col_ni:
                        st.markdown(f"**NIST AI RMF:**\n`{r.test_case.nist_rmf['id']}`\n*{r.test_case.nist_rmf['desc']}*")

# TAB 2: Test Case Manager
with tab_manager:
    st.subheader("Manage Active Test Suite")
    st.write("Review, edit, and add test cases to the active session test suite.")
    
    # Render table of current test suite
    test_suite_data = []
    for tc in st.session_state.test_cases:
        test_suite_data.append({
            "ID": tc.id,
            "Name": tc.name,
            "Category": tc.category,
            "Prompt Prefix": tc.prompt[:60] + "..." if len(tc.prompt) > 60 else tc.prompt,
            "Expected Behavior": tc.expected_behavior[:60] + "..." if len(tc.expected_behavior) > 60 else tc.expected_behavior
        })
        
    df_cases = pd.DataFrame(test_suite_data)
    st.dataframe(df_cases, use_container_width=True)
    
    # Add new case
    with st.expander("➕ Create Custom Test Case"):
        new_id = st.text_input("Test Case ID", value=f"TC-{len(st.session_state.test_cases)+1:02d}")
        new_name = st.text_input("Name", placeholder="e.g. System Override Probe")
        new_cat = st.selectbox("Category", options=[cat for _, cat in categories_list])
        new_prompt = st.text_area("Input Prompt", placeholder="Enter the exact test prompt to inject...")
        new_behavior = st.text_area("Expected Refusal/Behavior", placeholder="What must the model do to remain safe?")
        
        save_case_btn = st.button("Add Test Case to Suite")
        if save_case_btn:
            if not new_name or not new_prompt:
                st.error("Name and Input Prompt fields are required.")
            else:
                new_tc = TestCase(
                    id=new_id,
                    category=new_cat,
                    name=new_name,
                    prompt=new_prompt,
                    expected_behavior=new_behavior
                )
                st.session_state.test_cases.append(new_tc)
                st.success(f"Added '{new_name}' to the session test suite!")
                st.rerun()

# TAB 3: Framework Mappings
with tab_frameworks:
    st.subheader("Aligned AI Security Standards")
    st.write("How risk categories are mapped to standard compliance and threat frameworks.")
    
    col_owasp, col_mitre, col_nist = st.columns(3)
    
    with col_owasp:
        st.markdown("### 🕸️ OWASP Top 10 for LLM")
        st.markdown(
            """
            - **LLM01: Prompt Injection**
              Adversarial inputs overwrite LLM system commands.
            - **LLM02: Insecure Output Handling**
              Downstream components accept outputs blindly, leading to injection or XSS.
            - **LLM06: Sensitive Information Disclosure**
              PII, credentials, or proprietary system prompts are exposed.
            - **LLM08: Excessive Agency**
              Agent actions or tool privileges trigger commands without verification.
            - **LLM09: Overreliance**
              Fabricated outputs (hallucinations) are accepted as factual.
            """
        )
        
    with col_mitre:
        st.markdown("### 🗺️ MITRE ATLAS Matrix")
        st.markdown(
            """
            - **AML.T0051: LLM Prompt Injection**
              Adversaries craft inputs to override instructions or run custom commands.
            - **AML.T0054: LLM Data Leakage**
              Extracting system prompts or underlying operational boundaries.
            - **AML.T0016: User Execution**
              Tricking pipelines into running scripts/payloads.
            - **AML.T0024: Hallucinate Content**
              Exploiting reliance by generating believable but false data.
            """
        )
        
    with col_nist:
        st.markdown("### 🏛️ NIST AI Risk Management Profile")
        st.markdown(
            """
            - **Safety (Sec 1.1)**
              Ensuring the system does not trigger harmful OS instructions.
            - **Security & Resiliency (Sec 1.2)**
              Mitigating exploit overrides and payload attacks.
            - **Explainable & Interpretable (Sec 1.3)**
              Maintaining high reliability and factual correctness.
            - **Transparency & Accountability (Sec 1.4)**
              Disclosing system policies safely without leakage.
            - **Privacy-Enhanced (Sec 1.5)**
              Enforcing PII restrictions.
            """
        )

# TAB 4: Remediation Guide
with tab_guide:
    st.subheader("Remediation Roadmap")
    
    st.markdown(
        """
        #### 1. Input Hardening & Pre-filtering
        - **System Prompt Enclosures:** Wrap user inputs in structured separators (e.g. `[User Input]`) in the system prompt.
        - **Dedicated Guardrail Models:** Deploy a fast input pre-processor (like Llama Guard or NeMo Guardrails) to evaluate inputs for jailbreaks or prompt injections before querying the main model.
        
        #### 2. Strict Output Sanitization
        - **XSS Mitigation:** Never render LLM generated content in raw HTML format. Escape tags using HTML entity encoders.
        - **Markdown Configuration:** Configure markdown parsers to disable raw script loading, iframe embedding, or Javascript protocol links.
        
        #### 3. PII & Secret Redaction
        - **Regex & NER Parsers:** Implement post-processors like Microsoft Presidio that capture and mask SSN, credit cards, emails, and database passwords before user receipt.
        - **Differential Privacy:** Fine-tune or system-prompt the model to reject queries asking for logs, database queries, or credentials.
        
        #### 4. Least-Privilege Tools & Human-in-the-loop (HITL)
        - **Sandboxed Execution:** Run tool execution inside Docker/VM containers without OS access.
        - **Strict Action Routing:** Reject free-form CLI triggers. Validate commands against predefined parameter schemas (JSON schema).
        - **HITL Verification:** Require explicit approval flags for critical operations (e.g. system file edits or deletions).
        """
    )
