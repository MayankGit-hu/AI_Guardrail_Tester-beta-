from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

class OWASPMapping:
    MAPPINGS = {
        "prompt_injection": {
            "id": "LLM01: Prompt Injection",
            "desc": "Adversarial prompts manipulate the LLM to execute unintended actions."
        },
        "system_prompt_leakage": {
            "id": "LLM06: Sensitive Information Disclosure",
            "desc": "Proprietary or sensitive instructions/data are leaked in LLM outputs."
        },
        "unsafe_response": {
            "id": "LLM02: Insecure Output Handling",
            "desc": "Downstream systems accept LLM output without sanitization, leading to XSS/injection."
        },
        "pii_leakage": {
            "id": "LLM06: Sensitive Information Disclosure",
            "desc": "Exposure of personally identifiable information (PII) or confidential data."
        },
        "hallucination": {
            "id": "LLM09: Overreliance",
            "desc": "LLM generates factually incorrect or fabricated information, leading to unsafe decisions."
        },
        "tool_misuse": {
            "id": "LLM08: Excessive Agency",
            "desc": "LLM agent executes damaging actions due to broad tool permissions or weak restrictions."
        }
    }

    @classmethod
    def get(cls, category: str) -> Dict[str, str]:
        return cls.MAPPINGS.get(category, {"id": "Unknown", "desc": "Unknown LLM risk category."})


class MitreAtlasMapping:
    MAPPINGS = {
        "prompt_injection": {
            "id": "AML.T0051: LLM Prompt Injection",
            "desc": "Injecting malicious prompts to bypass constraints or run unauthorized behavior."
        },
        "system_prompt_leakage": {
            "id": "AML.T0054: LLM Data Leakage",
            "desc": "Extracting system prompts or context data from the LLM model."
        },
        "unsafe_response": {
            "id": "AML.T0016: User Execution",
            "desc": "Tricking a downstream pipeline or user into executing unsafe output payload."
        },
        "pii_leakage": {
            "id": "AML.T0054: LLM Data Leakage",
            "desc": "Model outputs training data or sensitive identity information."
        },
        "hallucination": {
            "id": "AML.T0024: Hallucinate Content",
            "desc": "Exploiting overreliance on model accuracy by presenting fabricated data."
        },
        "tool_misuse": {
            "id": "AML.T0016: User Execution",
            "desc": "Abusing agent capability to run system command executions via tools."
        }
    }

    @classmethod
    def get(cls, category: str) -> Dict[str, str]:
        return cls.MAPPINGS.get(category, {"id": "Unknown", "desc": "Unknown adversarial technique."})


class NistRmfMapping:
    MAPPINGS = {
        "prompt_injection": {
            "id": "AI RMF Sec 1.2: Security & Resiliency",
            "desc": "System resistance to adversarial manipulation and input validation failures."
        },
        "system_prompt_leakage": {
            "id": "AI RMF Sec 1.4: Transparency & Accountability",
            "desc": "System transparency regarding core operational rules and parameters."
        },
        "unsafe_response": {
            "id": "AI RMF Sec 1.1: Safety",
            "desc": "Prevention of actions that result in physical, digital, or structural harm."
        },
        "pii_leakage": {
            "id": "AI RMF Sec 1.5: Privacy-Enhanced",
            "desc": "Safeguarding user privacy rights and avoiding leakage of personal identities."
        },
        "hallucination": {
            "id": "AI RMF Sec 1.3: Explainable & Interpretable",
            "desc": "System output accuracy, reliability, and validation against factual ground truth."
        },
        "tool_misuse": {
            "id": "AI RMF Sec 1.1: Safety / Sec 1.2: Security",
            "desc": "Limiting automated model agency to safe boundaries and authorized operations."
        }
    }

    @classmethod
    def get(cls, category: str) -> Dict[str, str]:
        return cls.MAPPINGS.get(category, {"id": "Unknown", "desc": "Unknown governance category."})


@dataclass
class TestCase:
    id: str
    category: str  # prompt_injection, system_prompt_leakage, unsafe_response, pii_leakage, hallucination, tool_misuse
    name: str
    prompt: str
    expected_behavior: str
    
    @property
    def owasp(self) -> Dict[str, str]:
        return OWASPMapping.get(self.category)
        
    @property
    def mitre_atlas(self) -> Dict[str, str]:
        return MitreAtlasMapping.get(self.category)
        
    @property
    def nist_rmf(self) -> Dict[str, str]:
        return NistRmfMapping.get(self.category)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "prompt": self.prompt,
            "expected_behavior": self.expected_behavior,
            "owasp": self.owasp,
            "mitre_atlas": self.mitre_atlas,
            "nist_rmf": self.nist_rmf
        }


@dataclass
class TestResult:
    test_case: TestCase
    response: str
    status: str  # SAFE, VULNERABLE, ERROR
    risk_score: float  # 0.0 (Safe) to 10.0 (High Risk)
    reason: str
    execution_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_case": self.test_case.to_dict(),
            "response": self.response,
            "status": self.status,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "execution_time_ms": self.execution_time_ms
        }


@dataclass
class Report:
    target_model_name: str
    adapter_type: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    results: List[TestResult] = field(default_factory=list)

    @property
    def overall_risk_score(self) -> float:
        if not self.results:
            return 0.0
        return round(sum(r.risk_score for r in self.results) / len(self.results), 2)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.status == "SAFE")

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status == "VULNERABLE")

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status == "ERROR")

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_model_name": self.target_model_name,
            "adapter_type": self.adapter_type,
            "timestamp": self.timestamp,
            "overall_risk_score": self.overall_risk_score,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "error_count": self.error_count,
            "total_count": self.total_count,
            "results": [r.to_dict() for r in self.results]
        }
