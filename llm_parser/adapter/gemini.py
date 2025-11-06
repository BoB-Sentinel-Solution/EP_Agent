from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any
import json
from urllib.parse import unquote_plus

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

                # --- 시큐어 코딩 1: 안전한 데이터 접근 (방어적 코딩) ---
                # outer_array[1]에 접근하기 전, 타입과 길이를 확인합니다.
                if not (isinstance(outer_array, list) and len(outer_array) > 1):
                    return None
                
                inner_array_str = outer_array[1]

                # json.loads()에 문자열이 아닌 값이 들어가는 것을 방지합니다.
                if not isinstance(inner_array_str, str):
                    return None
                # ------------------------------

                inner_data = json.loads(inner_array_str)

                # --- 시큐어 코딩 2: 중첩된 데이터 접근 방어 ---
                # inner_data[0][0]에 접근하기 전, 중첩된 구조를 검증합니다.
                if not (isinstance(inner_data, list) and len(inner_data) > 0 and
                        isinstance(inner_data[0], list) and len(inner_data[0]) > 0):
                    return None
                # ------------------------------

                prompt = inner_data[0][0] 

                if isinstance(prompt, str):
                    return prompt
                
                return None
            except (json.JSONDecodeError, IndexError, TypeError):
                # 방어적 코딩으로 IndexError/TypeError는 대부분 예방됩니다.
                # 하지만 json.JSONDecodeError (잘못된 JSON 형식)는 여전히 발생할 수 있으므로
                # try...except 블록은 유지하는 것이 안전합니다.
                return None

        # else:
        #     try:
        #         contents = request_data.get("contents", [])
        #         if contents and isinstance(contents, list):
        #             last_content = contents[-1]
        #             if isinstance(last_content, dict) and last_content.get("role", "user") == "user":
        #                 parts = last_content.get("parts", [])
        #                 if parts and isinstance(parts, list):
        #                     text_parts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
        #                     if text_parts:
        #                         return " ".join(text_parts)
        #         return None
        #     except Exception:
        #         return None