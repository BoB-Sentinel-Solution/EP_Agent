
from llm_main import *

class GeminiAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Google Gemini API 프롬프트 추출"""
        try:
            # contents 패턴 처리
            contents = request_json.get("contents", [])
            if contents and isinstance(contents, list):
                last_content = contents[-1]
                if isinstance(last_content, dict):
                    parts = last_content.get("parts", [])
                    if parts and isinstance(parts, list):
                        for part in parts:
                            if isinstance(part, dict):
                                text_part = part.get("text")
                                if text_part:
                                    return text_part[:1000]
            
            # 기본 prompt 키 확인
            prompt = request_json.get("prompt")
            if prompt:
                return str(prompt)[:1000]
                
            return None
        except Exception:
            return None