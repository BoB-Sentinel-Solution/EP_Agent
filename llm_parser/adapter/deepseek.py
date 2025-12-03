from llm_parser.common.utils import LLMAdapter
from typing import Optional, Tuple
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
    
    
    def should_modify(self, host: str, content_type: str) -> bool:
        """DeepSeek 변조 대상 확인"""
        return (
            "chat.deepseek.com" in host and
            "application/json" in content_type
        )

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """DeepSeek 요청 데이터 변조"""
        try:
            # DeepSeek은 {"prompt": "..."} 구조
            if "prompt" not in request_data:
                return False, None

            request_data["prompt"] = modified_prompt
            modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
            return True, modified_content
        except Exception as e:
            print(f"[ERROR] DeepSeek 변조 실패: {e}")
            return False, None

