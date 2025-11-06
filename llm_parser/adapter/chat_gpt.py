from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, Tuple
import json
import logging
import base64

# 로깅 설정
logger = logging.getLogger(__name__)

# 보안 상수
MAX_PARTS_COUNT = 100  # parts 배열 최대 개수

# -------------------------------
# ChatGPT Adapter (보안 강화)
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """
        ChatGPT 전용 프롬프트 추출 (보안 강화)
        - 'content.parts' (리스트)와 'content.text' (문자열) 구조 모두 지원
        - 입력 검증 및 길이 제한 강화
        """
        try:
            # 입력 타입 검증
            if not isinstance(request_json, dict):
                logger.warning("request_json이 dict 타입이 아닙니다.")
                return None

            messages = request_json.get("messages", [])

            # 메시지 배열 검증
            if not isinstance(messages, list) or not messages:
                return None

            last_message = messages[-1]

            # 메시지 구조 검증
            if not isinstance(last_message, dict):
                logger.warning("last_message가 dict 타입이 아닙니다.")
                return None

            author = last_message.get("author", {})
            if not isinstance(author, dict) or author.get("role") != "user":
                return None

            content = last_message.get("content", {})
            if not isinstance(content, dict):
                logger.warning("content가 dict 타입이 아닙니다.")
                return None

            # Case 1: "parts" 키 확인 (e.g., ["하이"])
            parts = content.get("parts", [])
            if parts and isinstance(parts, list):
                # parts 배열 크기 제한 (DoS 방어)
                if len(parts) > MAX_PARTS_COUNT:
                    logger.warning(f"parts 배열이 너무 큽니다: {len(parts)}")
                    parts = parts[:MAX_PARTS_COUNT]

                text_parts_list = []
                for part in parts:
                    if isinstance(part, str):
                        # NULL 바이트 제거
                        sanitized = part.replace('\x00', '')
                        text_parts_list.append(sanitized)
                    elif isinstance(part, dict) and part.get("content_type") == "text":
                        # 멀티모달 호환
                        part_content = part.get("content", "")
                        if isinstance(part_content, str):
                            sanitized = part_content.replace('\x00', '')
                            text_parts_list.append(sanitized)

                if text_parts_list:
                    full_prompt = " ".join(text_parts_list)
                    print(f"[DEBUG ChatGPTAdapter] 'parts'에서 프롬프트 추출: {full_prompt[:50]}...")
                    return full_prompt[:1000]

            # Case 2: "text" 키 확인 (e.g., "하이")
            text = content.get("text")
            if text and isinstance(text, str):
                # NULL 바이트 제거
                sanitized_text = text.replace('\x00', '')
                print(f"[DEBUG ChatGPTAdapter] 'text'에서 프롬프트 추출: {sanitized_text[:50]}...")
                return sanitized_text[:1000]

            print("[DEBUG ChatGPTAdapter] 프롬프트 추출 실패. (구조 불일치)")
            return None

        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """
        ChatGPT 변조 대상 확인 (보안 강화)
        - 입력 타입 검증 추가
        """
        try:
            if not isinstance(host, str) or not isinstance(content_type, str):
                return False

            return (
                "chatgpt.com" in host and
                "application/json" in content_type.lower()
            )
        except Exception:
            return False

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """
        ChatGPT 요청 데이터 변조 (보안 강화)
        - 입력 검증 강화
        - 배열 인덱스 검증 추가
        - JSON 직렬화 예외 처리 추가
        """
        try:
            # 입력 타입 검증
            if not isinstance(request_data, dict):
                logger.warning("request_data가 dict 타입이 아닙니다.")
                return False, None

            if not isinstance(modified_prompt, str):
                logger.warning("modified_prompt가 str 타입이 아닙니다.")
                return False, None
            
            # NULL 바이트 제거
            modified_prompt = modified_prompt.replace('\x00', '')

            # JSON 구조 확인
            messages = request_data.get("messages", [])
            if not isinstance(messages, list) or not messages:
                logger.warning("messages가 유효하지 않습니다.")
                return False, None

            last_message = messages[-1]
            if not isinstance(last_message, dict):
                logger.warning("last_message가 dict 타입이 아닙니다.")
                return False, None

            author = last_message.get("author", {})
            if not isinstance(author, dict) or author.get("role") != "user":
                logger.warning("user role이 아닙니다.")
                return False, None

            # 프롬프트 변조
            content = last_message.get("content", {})
            if not isinstance(content, dict):
                logger.warning("content가 dict 타입이 아닙니다.")
                return False, None

            parts = content.get("parts", [])

            # 배열 검증 강화 (IndexError 방지)
            if not isinstance(parts, list) or not parts:
                logger.warning("parts 배열이 비어있습니다.")
                return False, None

            # 첫 번째 요소 타입 검증
            if not isinstance(parts[0], str):
                logger.warning("parts[0]이 문자열이 아닙니다.")
                return False, None

            # 프롬프트 변조 수행
            request_data['messages'][-1]['content']['parts'][0] = modified_prompt

            # JSON 직렬화 예외 처리
            try:
                modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
            except (TypeError, ValueError) as json_error:
                logger.error("JSON 직렬화 실패")
                return False, None

            # 변조된 콘텐츠 크기 검증
            if len(modified_content) > 10 * 1024 * 1024:  # 10MB 제한
                logger.warning(f"변조된 콘텐츠가 너무 큽니다: {len(modified_content)} bytes")
                return False, None

            return True, modified_content

        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None


