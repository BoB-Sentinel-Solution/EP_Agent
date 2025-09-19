from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any
import json
from urllib.parse import unquote_plus

# -------------------------------
# Gemini Adapter (수정된 버전)
# -------------------------------
class GeminiAdapter(LLMAdapter):
    def extract_prompt(self, request_data: Dict[str, Any], host: str) -> Optional[str]:
        """
        Gemini 트래픽에서 사용자 프롬프트를 추출합니다.
        Web UI 트래픽 (x-www-form-urlencoded)과 공식 API (json)를 모두 처리합니다.
        """
        if "gemini.google.com" in host and "f.req" in request_data:
            try:
                form_data_str = request_data.get("f.req")
                if not form_data_str:
                    return None

                decoded_str = unquote_plus(form_data_str)
                outer_array = json.loads(decoded_str)

                inner_array_str = outer_array[1]
                inner_data = json.loads(inner_array_str)

                prompt = inner_data[0][0] 

                if isinstance(prompt, str):
                    return prompt
                
                return None
            except (json.JSONDecodeError, IndexError, TypeError):
                return None

        else:
            try:
                contents = request_data.get("contents", [])
                if contents and isinstance(contents, list):
                    last_content = contents[-1]
                    if isinstance(last_content, dict) and last_content.get("role", "user") == "user":
                        parts = last_content.get("parts", [])
                        if parts and isinstance(parts, list):
                            text_parts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
                            if text_parts:
                                return " ".join(text_parts)
                return None
            except Exception:
                return None