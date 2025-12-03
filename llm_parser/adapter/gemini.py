from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, Tuple
import json
from urllib.parse import unquote_plus, urlencode

# -------------------------------
# Gemini Adapter (수정된 버전)
# -------------------------------
class GeminiAdapter(LLMAdapter):
    def extract_prompt(self, request_data: Dict[str, Any], host: str) -> Optional[str]:
        """
        Gemini 트래픽에서 사용자 프롬프트를 추출합니다.
        Web UI 트래픽 (x-www-form-urlencoded)과 공식 API (json)를 모두 처리합니다.
        """
        if "gemini.google.com" in host and "f.req" in request_data:
            try:
                form_data_str = request_data.get("f.req")
                if not form_data_str:
                    return None

                decoded_str = unquote_plus(form_data_str)
                outer_array = json.loads(decoded_str)

                inner_array_str = outer_array[1]
                inner_data = json.loads(inner_array_str)

                prompt = inner_data[0][0] 

                if isinstance(prompt, str):
                    return prompt

                return None
            except (json.JSONDecodeError, IndexError, TypeError):
                return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """Gemini 변조 대상 확인"""
        return (
            "gemini.google.com" in host and
            "application/x-www-form-urlencoded" in content_type
        )

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """Gemini 요청 데이터 변조 (중첩 JSON 구조)"""
        try:
            form_data_str = request_data.get("f.req")
            if not form_data_str:
                return False, None

            # URL 디코딩 → 외부 JSON 파싱
            decoded_str = unquote_plus(form_data_str)
            outer_array = json.loads(decoded_str)

            # 내부 JSON 파싱
            inner_array_str = outer_array[1]
            inner_data = json.loads(inner_array_str)

            # 프롬프트 수정
            inner_data[0][0] = modified_prompt

            # 역순으로 재구성
            outer_array[1] = json.dumps(inner_data, ensure_ascii=False)
            modified_freq = json.dumps(outer_array, ensure_ascii=False)

            # form data 재구성
            form_dict = dict(request_data)
            form_dict["f.req"] = modified_freq
            modified_content = urlencode(form_dict).encode('utf-8')

            return True, modified_content
        except Exception as e:
            print(f"[ERROR] Gemini 변조 실패: {e}")
            return False, None
