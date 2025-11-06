from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, List, Tuple
import json
import base64
import logging  # 로깅 추가
import re
import time

# 로깅 설정
logger = logging.getLogger(__name__)

# 보안 상수
MAX_PARTS_COUNT = 100  # content 내 parts 배열 최대 개수 (DoS 방어)
MAX_REQUEST_SIZE = 50 * 1024 * 1024 # 50MB (변조된 요청 최대 크기)

# -------------------------------
# Claude Adapter (보안 강화)
# -------------------------------
class ClaudeAdapter(LLMAdapter):
    
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Claude/Anthropic API 프롬프트 추출 (보안 강화)"""
        try:
            # 입력 타입 검증
            if not isinstance(request_json, dict):
                logger.warning("request_json이 dict 타입이 아닙니다.")
                return None

            logger.debug(f"[DEBUG Claude extract_prompt] request_json 키들: {list(request_json.keys())}")

            # Case 1: Claude.ai 웹 인터페이스 - prompt 키
            prompt = request_json.get("prompt")
            if prompt and isinstance(prompt, str):
                logger.debug(f"[DEBUG Claude extract_prompt] prompt 길이: {len(prompt)}")
                # NULL 바이트 제거
                return prompt.replace('\x00', '')[:1000]

            # Case 2: Anthropic API - messages 패턴
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                for message in reversed(messages):  # 최신 메시지부터 확인
                    if isinstance(message, dict) and message.get("role") == "user":
                        content = message.get("content")

                        # Case 2a: content가 문자열인 경우
                        if isinstance(content, str):
                            # NULL 바이트 제거
                            return content.replace('\x00', '')[:1000]

                        # Case 2b: content가 배열인 경우 (multimodal)
                        elif isinstance(content, list):
                            text_parts = []
                            # parts 배열 크기 제한 (DoS 방어)
                            parts_to_check = content[:MAX_PARTS_COUNT]
                            if len(content) > MAX_PARTS_COUNT:
                                logger.warning(f"Claude content 'parts' 배열이 너무 큽니다: {len(content)}")

                            for part in parts_to_check:
                                if isinstance(part, dict) and part.get("type") == "text":
                                    text_content = part.get("text", "")
                                    if isinstance(text_content, str):
                                        # NULL 바이트 제거
                                        sanitized = text_content.replace('\x00', '')
                                        text_parts.append(sanitized)
                            
                            if text_parts:
                                return " ".join(text_parts)[:1000]

            return None
        except Exception as e:
            # 예외 로깅
            logger.error(f"Claude extract_prompt 예외 발생: {e}")
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """Claude 변조 대상 확인 (보안 강화)"""
        try:
            # 입력 타입 검증
            if not isinstance(host, str) or not isinstance(content_type, str):
                return False

            return (
                ("claude.ai" in host or "api.anthropic.com" in host) and
                "application/json" in content_type.lower()  # .lower()로 안정성 확보
            )
        except Exception:
            return False  # 예외 발생 시 안전하게 False 반환

    def _serialize_and_validate(self, request_data: dict) -> Tuple[bool, Optional[bytes]]:
        """(Helper) JSON 직렬화 및 크기 검증"""
        try:
            modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
        except (TypeError, ValueError) as json_error:
            logger.error(f"JSON 직렬화 실패: {json_error}")
            return False, None
        
        # 변조된 콘텐츠 크기 검증
        if len(modified_content) > MAX_REQUEST_SIZE:
            logger.warning(f"변조된 콘텐츠가 너무 큽니다: {len(modified_content)} bytes")
            return False, None
        
        return True, modified_content

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """Claude 요청 데이터 변조 (보안 강화)"""
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

            # Case 1: Claude.ai 웹 인터페이스 - prompt 키 직접 수정
            if "prompt" in request_data and isinstance(request_data.get("prompt"), str):
                request_data["prompt"] = modified_prompt
                return self._serialize_and_validate(request_data)

            # Case 2: Anthropic API - messages 패턴 수정
            messages = request_data.get("messages", [])
            if isinstance(messages, list) and messages:
                for i, message in enumerate(reversed(messages)):
                    if isinstance(message, dict) and message.get("role") == "user":
                        content = message.get("content")
                        actual_index = len(messages) - 1 - i # 실제 인덱스

                        # Case 2a: content가 문자열인 경우
                        if isinstance(content, str):
                            request_data["messages"][actual_index]["content"] = modified_prompt
                            return self._serialize_and_validate(request_data)

                        # Case 2b: content가 배열인 경우 (multimodal) - 텍스트 부분만 수정
                        elif isinstance(content, list) and content: # content가 비어있지 않은지 확인
                            for j, part in enumerate(content):
                                if isinstance(part, dict) and part.get("type") == "text":
                                    # 첫 번째 텍스트 파트만 수정하고 반환
                                    request_data["messages"][actual_index]["content"][j]["text"] = modified_prompt
                                    return self._serialize_and_validate(request_data)
            
            logger.warning("Claude 변조 지점을 찾지 못했습니다.")
            return False, None
        
        except Exception as e:
            logger.error(f"Claude 변조 실패: {e}")
            return False, None