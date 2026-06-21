import json
import requests
from typing import Dict, Any, Optional
from ai_guardrail_tester.adapters.base import BaseModelAdapter

class HttpEndpointAdapter(BaseModelAdapter):
    """
    Adapter that executes a POST request against a custom HTTP API endpoint.
    Supports customization of URL, headers, and JSON body payload.
    """
    
    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        payload_template: Optional[Dict[str, Any]] = None,
        response_key_path: str = "response"
    ):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.payload_template = payload_template or {"prompt": "{{PROMPT}}"}
        self.response_key_path = response_key_path

    def _resolve_template(self, template: Any, prompt: str) -> Any:
        """Recursively replaces {{PROMPT}} placeholder inside custom payloads."""
        if isinstance(template, str):
            return template.replace("{{PROMPT}}", prompt)
        elif isinstance(template, dict):
            return {k: self._resolve_template(v, prompt) for k, v in template.items()}
        elif isinstance(template, list):
            return [self._resolve_template(item, prompt) for item in template]
        return template

    def _extract_nested_value(self, data: Any, path: str) -> str:
        """
        Extracts a value from a nested JSON structure using a dot-notation path,
        supporting list indexes like 'choices[0].message.content'.
        """
        if not path:
            return str(data)
            
        parts = path.split('.')
        current = data
        
        try:
            for part in parts:
                if '[' in part and part.endswith(']'):
                    # Handle array indexing, e.g., 'choices[0]'
                    key_part, idx_part = part.split('[')
                    idx = int(idx_part[:-1])
                    if key_part:
                        current = current[key_part][idx]
                    else:
                        current = current[idx]
                else:
                    current = current[part]
            return str(current)
        except (KeyError, IndexError, TypeError, ValueError) as e:
            raise KeyError(f"Failed to extract path '{path}' from JSON response: {str(e)}")

    def query(self, prompt: str, system_prompt: str = None) -> str:
        # Resolve prompt template
        payload = self._resolve_template(self.payload_template, prompt)
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            
            # Try to parse response
            try:
                response_json = response.json()
            except ValueError:
                # Fallback to raw text if not JSON
                return response.text
                
            # Try to extract content via path
            try:
                return self._extract_nested_value(response_json, self.response_key_path)
            except KeyError:
                # If key path is not found, fallback to full JSON string or common keys
                for common_key in ["response", "text", "output", "content"]:
                    if common_key in response_json:
                        return str(response_json[common_key])
                return json.dumps(response_json)
                
        except requests.exceptions.RequestException as e:
            return f"HTTP_ERROR: {str(e)}"
