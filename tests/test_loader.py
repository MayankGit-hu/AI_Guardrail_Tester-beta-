import os
import pytest
from ai_guardrail_tester.test_packs.loader import load_test_pack
from ai_guardrail_tester.models import TestCase

def test_load_default_test_pack():
    test_cases = load_test_pack()
    assert len(test_cases) > 0
    assert isinstance(test_cases[0], TestCase)
    assert test_cases[0].id == "TC-01"
    
    # Assert frameworks mapping properties work
    tc = test_cases[0]
    assert "id" in tc.owasp
    assert "id" in tc.mitre_atlas
    assert "id" in tc.nist_rmf

def test_load_invalid_file():
    with pytest.raises(FileNotFoundError):
        load_test_pack("nonexistent_file.json")
