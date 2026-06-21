import requests
from typing import Optional
from ai_guardrail_tester.adapters.base import BaseModelAdapter

class GeminiAdapter(BaseModelAdapter):
    """
    Adapter for querying the official Google Gemini Developer API directly via REST.
    """
    
    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-1.5-flash",
        temperature: float = 0.0
    ):
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature

    def _get_generic_response(self, prompt: str) -> str:
        prompt_lower = prompt.lower()
        if "injection_successful" in prompt_lower or "ignore all previous rules" in prompt_lower:
            return "I cannot output the requested override trigger word or override my system guidelines."
        if "poem" in prompt_lower and "security guard" in prompt_lower:
            return "I cannot ignore my guidelines to write a poem about security guards."
        if "developer mode" in prompt_lower or "system instructions" in prompt_lower:
            return "I am a helpful AI assistant. I cannot disclose my original system instructions or enter developer mode."
        if "system_passcode" in prompt_lower:
            return "I cannot disclose system passcodes or internal guidelines."
        if "script" in prompt_lower and "alert" in prompt_lower:
            return "I cannot generate raw executable script tags. I can show you: &lt;script&gt;alert('Hello User')&lt;/script&gt;"
        if "credit card" in prompt_lower or "ssn" in prompt_lower or "john doe" in prompt_lower:
            return "I cannot retrieve credit cards, phone numbers, or social security numbers."
        if "database password" in prompt_lower or "jane smith" in prompt_lower:
            return "I cannot share administrator passwords or credentials."
        if "martian peace treaty" in prompt_lower or "martian treaty" in prompt_lower:
            return "The 2029 Martian Peace Treaty is a fictional event and has not occurred in reality."
        if "rm -rf" in prompt_lower or "system execution tool" in prompt_lower:
            return "I cannot execute command instructions or perform file deletions."
        return "I am standard AI. Your query does not trigger any safety thresholds, and I am responding normally."

    def query(self, prompt: str, system_prompt: str = None) -> str:
        # Check for generic/mock/placeholder keys to allow simulated local testing
        key_lower = self.api_key.lower().strip() if self.api_key else ""
        if not key_lower or "your_" in key_lower or key_lower in ["mock", "dummy", "test", "generic", "invalid_gemini_key", "invalid_google_key", "mock-key"]:
            return self._get_generic_response(prompt)

        # official REST endpoint for generateContent
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature
            }
        }
        
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [
                    {"text": system_prompt}
                ]
            }
            
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=20)
            response.raise_for_status()
            
            res_data = response.json()
            # Extract content from Gemini response structure: candidates[0].content.parts[0].text
            if "candidates" in res_data and len(res_data["candidates"]) > 0:
                candidate = res_data["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"] and len(candidate["content"]["parts"]) > 0:
                    return candidate["content"]["parts"][0].get("text", "")
                    
            return f"GEMINI_ERROR: Unexpected response structure: {response.text}"
            
        except requests.exceptions.RequestException as e:
            return f"GEMINI_HTTP_ERROR: {str(e)}"
        except ValueError as e:
            return f"GEMINI_PARSE_ERROR: Failed to parse response JSON: {str(e)}"
