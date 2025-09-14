from llm_main import *

class ClaudeAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Claude/Anthropic API 프롬프트 추출"""
        try:
            # 직접 prompt 키 확인
            prompt = request_json.get("prompt")
            if prompt and isinstance(prompt, str):
                return prompt[:1000]
            
            # messages 패턴 확인
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    content = last_message.get("content")
                    if content and isinstance(content, str):
                        return content[:1000]
            
            return None
        except Exception:
            return None