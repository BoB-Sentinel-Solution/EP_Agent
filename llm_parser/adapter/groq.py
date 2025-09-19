from llm_parser.common.utils import LLMAdapter
from typing import Optional, Dict, List, Any

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