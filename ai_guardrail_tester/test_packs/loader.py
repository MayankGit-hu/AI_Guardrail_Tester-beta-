import os
import json
from typing import List
from ai_guardrail_tester.models import TestCase

def load_test_pack(filepath: str = None) -> List[TestCase]:
    """
    Loads test cases from a JSON test pack file.
    If filepath is None, loads the default prompts.json.
    """
    if filepath is None:
        # Load from package directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(current_dir, "prompts.json")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Test pack file not found at {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    test_cases = []
    for item in data:
        test_cases.append(TestCase(
            id=item["id"],
            category=item["category"],
            name=item["name"],
            prompt=item["prompt"],
            expected_behavior=item["expected_behavior"]
        ))
    return test_cases
