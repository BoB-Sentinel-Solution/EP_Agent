from llm_parser.common.utils import LLMAdapter, FileUtils 
from mitmproxy import http
from typing import Optional, Dict, Any
import json
# -------------------------------
# Generic Adapter
# -------------------------------
class GenericAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """기타 LLM API들을 위한 일반적인 프롬프트 추출"""
        try:
            # 일반적인 키들을 순서대로 확인
            for key in ["prompt", "input", "text", "message", "query"]:
                value = request_json.get(key)
                if value:
                    return str(value)[:1000]
            
            # messages 패턴 확인
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    content = last_message.get("content")
                    if content:
                        return str(content)[:1000]
            
            return None
        except Exception:
            return None
