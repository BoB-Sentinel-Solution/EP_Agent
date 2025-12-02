from llm_parser.common.utils import LLMAdapter
from typing import Optional, Dict, List, Any, Tuple
import json

# -------------------------------
# Groq Adapter 
# -------------------------------
class GroqAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Groq API (OpenAI 호환) 프롬프트 추출"""
        try:
            messages: List[Dict[str, Any]] = request_json.get("messages", [])
            if not messages:
                return None

            last_message = messages[-1]
            
            if isinstance(last_message, dict) and last_message.get("role") == "user":
                content = last_message.get("content")
                if not isinstance(content, str):
                    return None

                
                # Groq 웹사이트가 첫 프롬프트에 자동으로 추가하는 시스템 안내 문구
                SYSTEM_PROMPT = "Please try to provide useful, helpful and actionable answers.\n"
                
                # 만약 content가 해당 안내 문구로 시작한다면, 그 부분을 제거합니다.
                if content.startswith(SYSTEM_PROMPT):
                    # replace(old, new, count)를 사용하여 정확히 첫 부분만 제거
                    return content.replace(SYSTEM_PROMPT, '', 1) 
                
                
                return content

            return None
        except Exception:
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """Groq 변조 대상 확인"""
        return (
            "groq.com" in host and
            "application/json" in content_type
        )

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """Groq 요청 데이터 변조 (OpenAI 호환 구조)"""
        try:
            messages = request_data.get("messages", [])
            if not messages:
                return False, None

            last_message = messages[-1]
            if not isinstance(last_message, dict) or last_message.get("role") != "user":
                return False, None

            # Groq은 content가 직접 문자열
            request_data["messages"][-1]["content"] = modified_prompt
            modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
            return True, modified_content
        except Exception as e:
            print(f"[ERROR] Groq 변조 실패: {e}")
            return False, None