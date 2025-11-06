from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, Tuple
import json
import logging
import base64

# -------------------------------
# ChatGPT Adapter (통합됨)
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """
        ChatGPT 전용 프롬프트 추출 (수정됨)
        - 'content.parts' (리스트)와 'content.text' (문자열) 구조 모두 지원
        """
        try:
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    author = last_message.get("author", {})
                    if author.get("role") == "user":
                        content = last_message.get("content", {})
                        
                        # [수정] 2가지 경로 모두 확인
                        
                        # Case 1: "parts" 키 확인 (e.g., ["하이"])
                        parts = content.get("parts", [])
                        if parts and isinstance(parts, list):
                            text_parts_list = []
                            for part in parts:
                                if isinstance(part, str):
                                    text_parts_list.append(part)
                                elif isinstance(part, dict) and part.get("content_type") == "text":
                                    # (멀티모달 호환)
                                    text_parts_list.append(part.get("content", ""))
                            
                            if text_parts_list:
                                full_prompt = " ".join(text_parts_list)
                                print(f"[DEBUG ChatGPTAdapter] 'parts'에서 프롬프트 추출: {full_prompt[:50]}...")
                                return full_prompt[:1000]

                        # Case 2: "text" 키 확인 (e.g., "하이")
                        text = content.get("text")
                        if text and isinstance(text, str):
                            print(f"[DEBUG ChatGPTAdapter] 'text'에서 프롬프트 추출: {text[:50]}...")
                            return text[:1000]

            print("[DEBUG ChatGPTAdapter] 프롬프트 추출 실패. (구조 불일치)")
            return None
            
        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """ChatGPT 변조 대상 확인"""
        return (
            "chatgpt.com" in host and
            "application/json" in content_type
        )

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """ChatGPT 요청 데이터 변조"""
        try:
            # JSON 구조 확인
            messages = request_data.get("messages", [])
            if not messages:
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})
            if author.get("role") != "user":
                return False, None

            # 프롬프트 변조
            content = last_message.get("content", {})
            parts = content.get("parts", [])
            if parts and isinstance(parts[0], str):
                request_data['messages'][-1]['content']['parts'][0] = modified_prompt

                # 바이너리 변환
                modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
                return True, modified_content

            return False, None
        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None


