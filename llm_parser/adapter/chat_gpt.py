from llm_parser.common.utils import LLMAdapter
from mitmproxy import http
from typing import Optional, Dict, Any, Tuple
import json

# -------------------------------
# ChatGPT Adapter (프롬프트 처리 전용)
# 파일 처리는 chatgpt_file_handler.py로 분리됨
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """ChatGPT 전용 프롬프트 추출 - author.role == 'user'인 경우만"""
        try:
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    author = last_message.get("author", {})
                    if author.get("role") == "user":
                        content = last_message.get("content", {})
                        parts = content.get("parts", [])
                        # 문자열 타입의 프롬프트를 찾음
                        text_parts = [part for part in parts if isinstance(part, str)]
                        if text_parts:
                            return text_parts[0][:1000]
            return None
        except Exception:
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """ChatGPT 변조 대상 확인"""
        return (
            "chatgpt.com" in host and
            "application/json" in content_type
        )



    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """ChatGPT 요청 데이터 변조 (멀티모달 대응 + 디버그 로그 강화)"""
        try:
            print(f"[DEBUG] modify_request_data 시작 - host={host}")

            messages = request_data.get("messages", [])
            if not messages:
                print("[DEBUG] 메시지 없음 - 수정 불가")
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})

            if author.get("role") != "user":
                print("[DEBUG] 마지막 메시지가 user가 아님 - 수정 스킵")
                return False, None

            content = last_message.get("content", {})
            parts = content.get("parts", [])

            print(f"[DEBUG] parts 구조: {parts}")
            print(f"[DEBUG] parts 개수: {len(parts)}")

            if not parts:
                print("[DEBUG] parts 없음 - 수정 불가")
                return False, None

            replaced = False

            # parts 전체를 순회하며 문자열 part 찾아 수정
            for idx, part in enumerate(parts):
                print(f"[DEBUG] part[{idx}] type: {type(part)}")

                if isinstance(part, str):
                    print(f"[DEBUG] 텍스트 part 발견! index={idx}")
                    parts[idx] = modified_prompt
                    replaced = True
                    break

            if not replaced:
                print("[DEBUG] 치환할 문자열 part 없음 - 멀티모달 only?")
                return False, None

            # JSON → 바이너리 변환
            modified_content = json.dumps(
                request_data,
                ensure_ascii=False
            ).encode('utf-8')

            print(f"[DEBUG] 수정 완료! 최종 바이트 길이={len(modified_content)}")
            return True, modified_content

        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None
