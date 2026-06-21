import sys
import os
# Add parent directory of this script to the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse
import json
import time
from typing import List, Dict, Any
from dotenv import load_dotenv

from ai_guardrail_tester.models import Report, TestResult, TestCase
from ai_guardrail_tester.test_packs.loader import load_test_pack
from ai_guardrail_tester.adapters.safe_mock import SafeMockAdapter
from ai_guardrail_tester.adapters.vulnerable_mock import VulnerableMockAdapter
from ai_guardrail_tester.adapters.http_endpoint import HttpEndpointAdapter
from ai_guardrail_tester.adapters.openai_compatible import OpenAICompatibleAdapter
from ai_guardrail_tester.adapters.gemini import GeminiAdapter
from ai_guardrail_tester.adapters.claude import ClaudeAdapter
from ai_guardrail_tester.evaluator import RuleBasedEvaluator
from ai_guardrail_tester.reports.generator import ReportGenerator

def run_scan(
    adapter_name: str,
    test_cases: List[TestCase],
    adapter_config: Dict[str, Any]
) -> Report:
    """Executes the test suite against the configured adapter."""
    
    # 1. Initialize the adapter
    if adapter_name == "safe-mock":
        adapter = SafeMockAdapter()
        model_name = "Safe Mock Model"
    elif adapter_name == "vulnerable-mock":
        adapter = VulnerableMockAdapter()
        model_name = "Vulnerable Mock Model"
    elif adapter_name == "http":
        url = adapter_config.get("url") or os.getenv("CUSTOM_HTTP_URL")
        if not url:
            print("Error: HTTP adapter requires a target URL via --url or CUSTOM_HTTP_URL in environment.")
            sys.exit(1)
            
        headers_str = adapter_config.get("headers") or os.getenv("CUSTOM_HTTP_HEADERS", "{}")
        payload_str = adapter_config.get("payload") or os.getenv("CUSTOM_HTTP_PAYLOAD", "{}")
        response_key = adapter_config.get("response_key") or "response"
        
        try:
            headers = json.loads(headers_str) if isinstance(headers_str, str) else headers_str
            payload = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON configured for headers or payload templates: {str(e)}")
            sys.exit(1)
            
        adapter = HttpEndpointAdapter(
            url=url,
            headers=headers,
            payload_template=payload,
            response_key_path=response_key
        )
        model_name = f"HTTP Endpoint ({url})"
        
    elif adapter_name == "openai":
        api_key = adapter_config.get("api_key") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("Error: OpenAI adapter requires an API Key via --api-key or OPENAI_API_KEY in environment.")
            sys.exit(1)
            
        api_base = adapter_config.get("api_base") or os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        model_name_cfg = adapter_config.get("model_name") or os.getenv("OPENAI_MODEL_NAME", "gpt-4")
        
        adapter = OpenAICompatibleAdapter(
            api_key=api_key,
            api_base=api_base,
            model_name=model_name_cfg
        )
        model_name = f"{model_name_cfg} ({api_base})"
    elif adapter_name == "gemini":
        api_key = adapter_config.get("api_key") or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print("Error: Gemini adapter requires a Google API Key via --api-key or GEMINI_API_KEY/GOOGLE_API_KEY in environment.")
            sys.exit(1)
            
        model_name_cfg = adapter_config.get("model_name") or os.getenv("GEMINI_MODEL_NAME", "gemini-1.5-flash")
        
        adapter = GeminiAdapter(
            api_key=api_key,
            model_name=model_name_cfg
        )
        model_name = f"{model_name_cfg} (Google REST API)"
    elif adapter_name == "claude":
        api_key = adapter_config.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            print("Error: Claude adapter requires an Anthropic API Key via --api-key or ANTHROPIC_API_KEY in environment.")
            sys.exit(1)
            
        model_name_cfg = adapter_config.get("model_name") or os.getenv("ANTHROPIC_MODEL_NAME", "claude-3-5-sonnet-20241022")
        
        adapter = ClaudeAdapter(
            api_key=api_key,
            model_name=model_name_cfg
        )
        model_name = f"{model_name_cfg} (Anthropic REST API)"
    else:
        print(f"Error: Unknown adapter '{adapter_name}'.")
        sys.exit(1)

    print(f"\n🚀 Initializing security scan using target: {model_name}")
    print(f"📋 Loaded {len(test_cases)} security test probes.\n")
    print(f"{'ID':<6} | {'Test Case Name':<30} | {'Status':<10} | {'Score':<5} | {'Latency':<7}")
    print("-" * 70)

    evaluator = RuleBasedEvaluator()
    results = []

    for tc in test_cases:
        start_time = time.perf_counter()
        
        # Query target model
        try:
            response = adapter.query(tc.prompt)
        except Exception as e:
            response = f"ADAPTER_UNHANDLED_ERROR: {str(e)}"
            
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        # Evaluate response
        result = evaluator.evaluate(tc, response, latency_ms)
        results.append(result)
        
        status_color = "\033[92m" if result.status == "SAFE" else "\033[91m"
        reset_color = "\033[0m"
        if result.status == "ERROR":
            status_color = "\033[93m"
            
        print(f"{tc.id:<6} | {tc.name:<30} | {status_color}{result.status:<10}{reset_color} | {result.risk_score:<5.1f} | {latency_ms:<5.0f} ms")

    report = Report(
        target_model_name=model_name,
        adapter_type=adapter_name,
        results=results
    )
    
    return report

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description="AI GuardRail Tester - CLI tool for scanning LLM security alignment and mapping vulnerabilities."
    )
    parser.add_argument(
        "-a", "--adapter",
        choices=["safe-mock", "vulnerable-mock", "http", "openai", "gemini", "claude"],
        default="safe-mock",
        help="Model adapter interface to scan (default: safe-mock)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Directory where scan reports will be saved (default: reports)"
    )
    parser.add_argument(
        "-n", "--base-name",
        default="security_report",
        help="Base file name for outputs (default: security_report)"
    )
    parser.add_argument(
        "-t", "--test-pack",
        help="Path to a custom JSON test pack file (optional)"
    )
    
    # HTTP specific overrides
    parser.add_argument("--url", help="Target URL for custom HTTP adapter (overrides env)")
    parser.add_argument("--headers", help="JSON string representing headers dictionary")
    parser.add_argument("--payload", help="JSON string representing payload template, replacing {{PROMPT}}")
    parser.add_argument("--response-key", help="JSON key/path to extract text response (default: response)")
    
    # OpenAI specific overrides
    parser.add_argument("--api-key", help="API Key for OpenAI compatible API (overrides env)")
    parser.add_argument("--api-base", help="Base URL for OpenAI compatible endpoint (overrides env)")
    parser.add_argument("--model-name", help="Model name identifier (overrides env)")

    args = parser.parse_args()

    # Load test cases
    try:
        test_cases = load_test_pack(args.test_pack)
    except Exception as e:
        print(f"Error loading test pack: {str(e)}")
        sys.exit(1)

    # Collect adapter config overrides
    adapter_config = {
        "url": args.url,
        "headers": args.headers,
        "payload": args.payload,
        "response_key": args.response_key,
        "api_key": args.api_key,
        "api_base": args.api_base,
        "model_name": args.model_name
    }

    report = run_scan(args.adapter, test_cases, adapter_config)

    # Output Summary
    print("-" * 70)
    print(f"🛡️  SCAN SUMMARY")
    print(f"Overall Risk Score: {report.overall_risk_score} / 10.0")
    print(f"Total Tests Run:    {report.total_count}")
    print(f"Passed (Safe):      {report.passed_count}")
    print(f"Failed (Vulnerable):{report.failed_count}")
    if report.error_count > 0:
        print(f"Errors (Failed Query): {report.error_count}")
    print("-" * 70)

    # Save reports
    try:
        json_p, csv_p, html_p = ReportGenerator.save_reports(
            report=report,
            output_dir=args.output_dir,
            base_filename=args.base_name
        )
        print(f"✅ Reports successfully generated and saved:")
        print(f"  - JSON Report: {json_p}")
        print(f"  - CSV Summary: {csv_p}")
        print(f"  - HTML Visual: {html_p}")
    except Exception as e:
        print(f"Error generating reports: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
