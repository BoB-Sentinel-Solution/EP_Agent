from llm_parser.common.utils import LLMAdapter, FileUtils 
from mitmproxy import http
from typing import Optional, Dict, Any
import json

# -------------------------------
# DeepSeek Adapter
# -------------------------------

class DeepSeekAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """DeepSeek 웹 채팅 프롬프트 추출"""
        try:
            # 요청된 JSON에서 'prompt' 키의 값을 바로 반환합니다.
            # 구조가 매우 간단하여 이 한 줄이면 충분합니다.
            prompt = request_json.get("prompt")
            
            if isinstance(prompt, str):
                return prompt
            
            return None
        except Exception:
            # 예외 발생 시 안전하게 None을 반환합니다.
            return None

