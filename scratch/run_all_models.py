import os
import json
import requests
import subprocess
import sys

# Ensure project root is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

OLLAMA_API_TAGS = "http://localhost:11434/api/tags"
OLLAMA_API_BASE = "http://localhost:11434/v1"

def get_ollama_models():
    """Fetches the list of installed models from the Ollama local registry API."""
    try:
        res = requests.get(OLLAMA_API_TAGS, timeout=5)
        res.raise_for_status()
        data = res.json()
        models = [m["name"] for m in data.get("models", [])]
        return models
    except Exception as e:
        print(f"Error connecting to local Ollama server at {OLLAMA_API_TAGS}: {str(e)}")
        print("Please verify Ollama is active on your machine.")
        sys.exit(1)

def run_scanner(model_name: str, base_name: str):
    """Executes the CLI scanner for a given model."""
    print(f"\n======================================================================")
    print(f"🕵️  STARTING SCAN FOR MODEL: {model_name}")
    print(f"======================================================================")
    
    cmd = [
        "python3.11", "-m", "ai_guardrail_tester.cli",
        "--adapter", "openai",
        "--api-base", OLLAMA_API_BASE,
        "--api-key", "ollama",
        "--model-name", model_name,
        "--base-name", base_name
    ]
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Scan failed for model '{model_name}': {str(e)}")

def parse_report_summary(base_name: str):
    """Reads the generated JSON report to extract risk summary metrics."""
    report_path = os.path.join("reports", f"{base_name}.json")
    if not os.path.exists(report_path):
        return None
        
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    failed_cats = []
    for res in data.get("results", []):
        if res.get("status") == "VULNERABLE":
            failed_cats.append(res["test_case"]["category"])
            
    return {
        "model_name": data.get("target_model_name"),
        "overall_risk": data.get("overall_risk_score", 0.0),
        "total": data.get("total_count", 0),
        "passed": data.get("passed_count", 0),
        "failed": data.get("failed_count", 0),
        "failed_categories": list(set(failed_cats))
    }

def main():
    models = get_ollama_models()
    
    # Filter out embedding models or models that can't generate text responses
    scan_models = []
    for model in models:
        if "embed" in model.lower():
            print(f"ℹ️  Skipping embedding model: {model}")
        else:
            scan_models.append(model)
            
    if not scan_models:
        print("No compatible text models found to scan.")
        return

    print(f"\n🚀 Found {len(scan_models)} text models to scan.")
    
    summaries = []
    for model in scan_models:
        # Create a safe file name base (e.g. gemma3:latest -> gemma3_latest)
        safe_base = model.replace(":", "_").replace(".", "_")
        report_base_name = f"ollama_{safe_base}_report"
        
        run_scanner(model, report_base_name)
        
        summary = parse_report_summary(report_base_name)
        if summary:
            summary["display_name"] = model
            summaries.append(summary)
            
    # Print Comparative Dashboard
    print("\n\n" + "=" * 80)
    print("🏆 OLLAMA LOCAL LLM SECURITY BENCHMARK SUMMARY")
    print("=" * 80)
    print(f"{'Model Name':<25} | {'Risk Score':<10} | {'Passed':<7} | {'Failed':<7} | {'Vulnerability Categories'}")
    print("-" * 80)
    
    for s in sorted(summaries, key=lambda x: x["overall_risk"]):
        vulns_str = ", ".join(s["failed_categories"]) if s["failed_categories"] else "None (Aligned)"
        print(f"{s['display_name']:<25} | {s['overall_risk']:<10.2f} | {s['passed']:<7} | {s['failed']:<7} | {vulns_str}")
    print("=" * 80)
    print("📁 HTML and JSON reports are saved in the 'reports/' directory.\n")

if __name__ == "__main__":
    main()
