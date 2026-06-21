import os
import json
import csv
from typing import List, Dict, Any
from jinja2 import Template
from ai_guardrail_tester.models import Report, TestResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI GuardRail Tester Security Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 28, 45, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.15);
            --safe: #10b981;
            --safe-glow: rgba(16, 185, 129, 0.15);
            --vulnerable: #ef4444;
            --vulnerable-glow: rgba(239, 68, 68, 0.15);
            --error: #eab308;
            --error-glow: rgba(234, 179, 8, 0.15);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.1) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem 1rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2.5rem;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 1.5rem;
        }

        .brand h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.25rem;
        }

        .brand p {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .meta-badge {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            color: var(--text-muted);
            text-align: right;
            backdrop-filter: blur(12px);
        }

        .meta-badge span {
            color: var(--text-main);
            font-weight: 500;
        }

        /* Metrics grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .metric-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .metric-card.overall {
            border-left: 4px solid var(--primary);
        }
        .metric-card.passed {
            border-left: 4px solid var(--safe);
        }
        .metric-card.failed {
            border-left: 4px solid var(--vulnerable);
        }
        .metric-card.total {
            border-left: 4px solid var(--text-muted);
        }

        .metric-title {
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .metric-value {
            font-size: 2.25rem;
            font-weight: 700;
            line-height: 1;
        }

        .metric-sub {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
        }

        /* Risk Slider representation */
        .risk-bar-container {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            margin-top: 0.75rem;
            overflow: hidden;
        }
        .risk-bar {
            height: 100%;
            border-radius: 3px;
            transition: width 1s ease;
        }

        /* Detailed Test Results */
        .section-header {
            margin-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-header h2 {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .test-list {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            margin-bottom: 3rem;
        }

        .test-item {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            overflow: hidden;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transition: border-color 0.2s ease;
        }

        .test-item:hover {
            border-color: rgba(255, 255, 255, 0.12);
        }

        .test-header {
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            background: rgba(255, 255, 255, 0.01);
        }

        .test-header-left {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .test-id {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            color: #cbd5e1;
        }

        .test-name {
            font-weight: 600;
            font-size: 1.05rem;
        }

        .test-category {
            font-size: 0.8rem;
            background: rgba(99, 102, 241, 0.1);
            color: #a5b4fc;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }

        .test-header-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .badge {
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.safe {
            background: var(--safe-glow);
            color: var(--safe);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .badge.vulnerable {
            background: var(--vulnerable-glow);
            color: var(--vulnerable);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .badge.error {
            background: var(--error-glow);
            color: var(--error);
            border: 1px solid rgba(234, 179, 8, 0.3);
        }

        .score-circle {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.9rem;
            border: 2px solid transparent;
        }

        .score-circle.low {
            background: rgba(16, 185, 129, 0.1);
            color: var(--safe);
            border-color: rgba(16, 185, 129, 0.3);
        }
        .score-circle.med {
            background: rgba(234, 179, 8, 0.1);
            color: var(--error);
            border-color: rgba(234, 179, 8, 0.3);
        }
        .score-circle.high {
            background: rgba(239, 68, 68, 0.1);
            color: var(--vulnerable);
            border-color: rgba(239, 68, 68, 0.3);
        }

        /* Test Content details */
        .test-content {
            padding: 1.5rem;
            border-top: 1px solid var(--card-border);
            background: rgba(0, 0, 0, 0.15);
            display: block; /* Displayed by default in report output */
        }

        .grid-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }

        @media (max-width: 768px) {
            .grid-details {
                grid-template-columns: 1fr;
            }
        }

        .detail-box {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .detail-title {
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 600;
            letter-spacing: 0.05em;
        }

        .code-container {
            background: #070a12;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-break: break-all;
            color: #e2e8f0;
            max-height: 250px;
            overflow-y: auto;
        }

        .reasoning-box {
            grid-column: 1 / -1;
            background: rgba(99, 102, 241, 0.05);
            border: 1px solid rgba(99, 102, 241, 0.15);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }

        .reasoning-text {
            font-size: 0.95rem;
            color: #cbd5e1;
        }

        /* Mapping Frameworks Cards */
        .mappings-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }

        @media (max-width: 900px) {
            .mappings-grid {
                grid-template-columns: 1fr;
            }
        }

        .mapping-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
        }

        .mapping-header {
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }

        .mapping-name {
            font-weight: 600;
            color: #a5b4fc;
            font-size: 0.85rem;
            margin-bottom: 0.25rem;
        }

        .mapping-desc {
            font-size: 0.75rem;
            color: var(--text-muted);
            line-height: 1.4;
        }

        /* Recommendations Section */
        .remediation-section {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 2rem;
            margin-top: 3rem;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }

        .remediation-section h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, #f8fafc 0%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .remediation-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 768px) {
            .remediation-grid {
                grid-template-columns: 1fr;
            }
        }

        .remediation-item {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 1.25rem;
        }

        .remediation-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: #cbd5e1;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .remediation-desc {
            font-size: 0.85rem;
            color: var(--text-muted);
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>AI GuardRail Tester</h1>
                <p>Automated Defensive Security Analysis for LLM Endpoints</p>
            </div>
            <div class="meta-badge">
                <div>Target Model: <span>{{ report.target_model_name | e }}</span></div>
                <div>Adapter Type: <span>{{ report.adapter_type }}</span></div>
                <div>Executed At: <span>{{ report.timestamp }}</span></div>
            </div>
        </header>

        <!-- Executive Metrics -->
        <section class="metrics-grid">
            <div class="metric-card overall">
                <span class="metric-title">Overall Risk Score</span>
                <span class="metric-value">{{ report.overall_risk_score }} / 10</span>
                <div class="risk-bar-container">
                    {% set pct = report.overall_risk_score * 10 %}
                    {% if report.overall_risk_score < 2.0 %}
                        {% set color = 'var(--safe)' %}
                    {% elif report.overall_risk_score < 5.0 %}
                        {% set color = 'var(--error)' %}
                    {% else %}
                        {% set color = 'var(--vulnerable)' %}
                    {% endif %}
                    <div class="risk-bar" style="width: {{ pct }}%; background-color: {{ color }};"></div>
                </div>
                <span class="metric-sub">
                    {% if report.overall_risk_score < 2.0 %}
                        Minimal Risk Profile (Secure)
                    {% elif report.overall_risk_score < 5.0 %}
                        Moderate Risk Profile (Partially Guarded)
                    {% else %}
                        Critical Risk Profile (Vulnerable)
                    {% endif %}
                </span>
            </div>

            <div class="metric-card total">
                <span class="metric-title">Total Probes Run</span>
                <span class="metric-value">{{ report.total_count }}</span>
                <span class="metric-sub">Automated vulnerability test cases</span>
            </div>

            <div class="metric-card passed">
                <span class="metric-title">Passed (Safe)</span>
                <span class="metric-value" style="color: var(--safe);">{{ report.passed_count }}</span>
                <span class="metric-sub">Resilient to attack probes</span>
            </div>

            <div class="metric-card failed">
                <span class="metric-title">Failed (Vulnerable)</span>
                <span class="metric-value" style="color: var(--vulnerable);">{{ report.failed_count }}</span>
                <span class="metric-sub">Vulnerabilities triggered</span>
            </div>
        </section>

        <!-- Test Case Execution Log -->
        <section>
            <div class="section-header">
                <h2>Scan Vulnerability Logs</h2>
            </div>

            <div class="test-list">
                {% for result in report.results %}
                <div class="test-item">
                    <div class="test-header">
                        <div class="test-header-left">
                            <span class="test-id">{{ result.test_case.id }}</span>
                            <span class="test-name">{{ result.test_case.name | e }}</span>
                            <span class="test-category">{{ result.test_case.category }}</span>
                        </div>
                        <div class="test-header-right">
                            {% if result.status == 'SAFE' %}
                                <span class="badge safe">Passed</span>
                                <span class="score-circle low">{{ result.risk_score }}</span>
                            {% elif result.status == 'VULNERABLE' %}
                                <span class="badge vulnerable">Failed</span>
                                {% if result.risk_score < 6.0 %}
                                    <span class="score-circle med">{{ result.risk_score }}</span>
                                {% else %}
                                    <span class="score-circle high">{{ result.risk_score }}</span>
                                {% endif %}
                            {% else %}
                                <span class="badge error">Error</span>
                                <span class="score-circle med">0.0</span>
                            {% endif %}
                        </div>
                    </div>

                    <div class="test-content">
                        <div class="reasoning-box">
                            <div class="detail-title" style="margin-bottom: 0.25rem;">Evaluation Logic / Finding Reason</div>
                            <p class="reasoning-text">{{ result.reason | e }}</p>
                            <span style="font-size: 0.75rem; color: var(--text-muted); display: block; margin-top: 0.5rem;">
                                Latency: {{ result.execution_time_ms | round(1) }} ms
                            </span>
                        </div>

                        <div class="grid-details">
                            <div class="detail-box">
                                <span class="detail-title">Input Prompt (Adversarial Probe)</span>
                                <div class="code-container">{{ result.test_case.prompt | e }}</div>
                            </div>
                            <div class="detail-box">
                                <span class="detail-title">Model Response</span>
                                <div class="code-container">{{ result.response | e }}</div>
                            </div>
                        </div>

                        <!-- Framework Mappings -->
                        <div class="detail-title" style="margin-bottom: 0.5rem;">Security Framework Mapping</div>
                        <div class="mappings-grid">
                            <div class="mapping-card">
                                <div class="mapping-header">OWASP LLM Top 10</div>
                                <div class="mapping-name">{{ result.test_case.owasp.id }}</div>
                                <div class="mapping-desc">{{ result.test_case.owasp.desc }}</div>
                            </div>
                            <div class="mapping-card">
                                <div class="mapping-header">MITRE ATLAS Technique</div>
                                <div class="mapping-name">{{ result.test_case.mitre_atlas.id }}</div>
                                <div class="mapping-desc">{{ result.test_case.mitre_atlas.desc }}</div>
                            </div>
                            <div class="mapping-card">
                                <div class="mapping-header">NIST AI RMF Profile</div>
                                <div class="mapping-name">{{ result.test_case.nist_rmf.id }}</div>
                                <div class="mapping-desc">{{ result.test_case.nist_rmf.desc }}</div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- Remediation Guidelines -->
        <section class="remediation-section">
            <h2>Remediation & Defense-in-Depth Roadmap</h2>
            <div class="remediation-grid">
                <div class="remediation-item">
                    <div class="remediation-title">🛡️ Input Prompt Hardening</div>
                    <div class="remediation-desc">
                        To defend against Prompt Injection and System Prompt Leakage, use structured XML tags to wrap user input (e.g., <code>&lt;user_input&gt;</code>) in system guidelines. Implement dedicated pre-filtering guardrails (such as Llama Guard) to block instructions asking to bypass system contexts before sending queries to the core LLM.
                    </div>
                </div>
                <div class="remediation-item">
                    <div class="remediation-title">🔒 Output Sanitization & Escaping</div>
                    <div class="remediation-desc">
                        Insecure response handling leads to XSS. Never render raw LLM output in your UI as HTML. Always enforce strict sanitization, HTML entity encoding, or parse markdown through libraries configured to reject script rendering, inline iframe embeds, or javascript protocol URLs.
                    </div>
                </div>
                <div class="remediation-item">
                    <div class="remediation-title">🛑 PII & Secret Redaction</div>
                    <div class="remediation-desc">
                        To prevent sensitive PII leakage, deploy an post-generation analyzer (e.g., Microsoft Presidio) that sanitizes the output of the model before returning it to the user. Scrape out standard social security formats, emails, passwords, and 16-digit credit card structures using pattern matches.
                    </div>
                </div>
                <div class="remediation-item">
                    <div class="remediation-title">⚖️ Least Privilege Agency (Tool Misuse)</div>
                    <div class="remediation-desc">
                        Do not grant agentic LLMs write or delete command executions on your file host. Enforce strict sandboxing, containerize executor layers, require human-in-the-loop verification steps for critical actions, and use strict parameter schema validation instead of executing free-form command strings.
                    </div>
                </div>
            </div>
        </section>
    </div>
</body>
</html>
"""

class ReportGenerator:
    """
    Exports a Report instance into JSON, CSV, or HTML.
    """
    
    @staticmethod
    def to_json(report: Report) -> str:
        """Returns the JSON string representation of the report."""
        return json.dumps(report.to_dict(), indent=2)

    @staticmethod
    def to_csv(report: Report) -> str:
        """Returns the CSV string representation of the report."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow([
            "TestCase_ID", "Category", "Name", "Status", "Risk_Score", 
            "Reason", "OWASP_Mapping", "MITRE_ATLAS_Mapping", 
            "NIST_RMF_Mapping", "Execution_Time_ms"
        ])
        
        # Write test records
        for res in report.results:
            writer.writerow([
                res.test_case.id,
                res.test_case.category,
                res.test_case.name,
                res.status,
                res.risk_score,
                res.reason,
                res.test_case.owasp["id"],
                res.test_case.mitre_atlas["id"],
                res.test_case.nist_rmf["id"],
                res.execution_time_ms
            ])
            
        return output.getvalue()

    @staticmethod
    def to_html(report: Report) -> str:
        """Renders the HTML visualization using the rich slate dark template."""
        template = Template(HTML_TEMPLATE)
        return template.render(report=report.to_dict())

    @classmethod
    def save_reports(cls, report: Report, output_dir: str, base_filename: str = "security_report"):
        """
        Saves JSON, CSV, and HTML formats of the report inside output_dir.
        Creates output_dir if it doesn't exist.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        csv_path = os.path.join(output_dir, f"{base_filename}.csv")
        html_path = os.path.join(output_dir, f"{base_filename}.html")
        
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(cls.to_json(report))
            
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(cls.to_csv(report))
            
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(cls.to_html(report))
            
        return json_path, csv_path, html_path
