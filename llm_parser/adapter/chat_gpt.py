import os
import json
import logging
from typing import Optional, Dict, Any, Tuple
from mitmproxy import http
from datetime import datetime
from llm_parser.common.utils import LLMAdapter, FileUtils

UNIFIED_LOG_PATH = "./unified_request.json"

class ChatGPTAdapter(LLMAdapter):
    """ChatGPT 트래픽용 어댑터 (role 기반 분기 + MCP 추적 포함)"""

    def _save_unified_log(self, data: dict):
        """unified_request.json에 로그 append"""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(UNIFIED_LOG_PATH)) or ".", exist_ok=True)
            with open(UNIFIED_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[ERROR] unified_request.json 기록 실패: {e}")

    # -------------------------------
    # 핵심: ChatGPT 전용 프롬프트 추출
    # -------------------------------
    # [수정] 반환 타입을 Optional[dict]로 변경
    def extract_prompt(self, request_json: dict, host: str, path: str = None) -> Optional[dict]: 
        try:
            messages = request_json.get("messages", [])
            if not isinstance(messages, list) or not messages:
                return None

            last_message = messages[-1]
            author = last_message.get("author", {})
            role = author.get("role")
            name = author.get("name")

            # --- Case 1: user role ---
            if role == "user":
                # system_hints 체크 (agent 있으면 MCP, 없으면 LLM)
                metadata = last_message.get("metadata", {})
                system_hints = metadata.get("system_hints", [])

                has_agent = False
                if isinstance(system_hints, list):
                    has_agent = "agent" in system_hints
                elif isinstance(system_hints, str):
                    has_agent = "agent" in system_hints

                # 프롬프트 추출
                content = last_message.get("content", {})
                parts = content.get("parts", [])
                text = content.get("text")

                extracted_prompt = None
                if parts and isinstance(parts, list):
                    text_parts_list = []
                    for part in parts:
                        if isinstance(part, str):
                            text_parts_list.append(part)
                        elif isinstance(part, dict) and part.get("content_type") == "text":
                            text_parts_list.append(part.get("content", ""))
                    if text_parts_list:
                        extracted_prompt = " ".join(text_parts_list)[:1000]
                        print(f"[DEBUG ChatGPTAdapter] user role 프롬프트 추출: {extracted_prompt[:50]}...")

                if not extracted_prompt and text and isinstance(text, str):
                    extracted_prompt = text[:1000]
                    print(f"[DEBUG ChatGPTAdapter] user role text 추출: {extracted_prompt[:50]}...")

                # --- [!!!] 핵심 수정 지점 ---
                if extracted_prompt:
                    interface = "mcp" if has_agent else "llm"
                    
                    # [수정] 로그를 직접 저장하는 대신,
                    # 상위 로거(llm_main.py)가 처리할 dict를 반환합니다.
                    result = {
                        "prompt": extracted_prompt,
                        # llm_main.py가 attachment를 기대할 수 있으므로 호환성을 위해 추가
                        "attachment": {"format": None, "data": None}, 
                        "interface": interface
                    }
                    print(f"[DEBUG ChatGPTAdapter] 프롬프트 추출 완료 (interface={interface}): {extracted_prompt[:50]}...")
                    # [수정] 문자열이 아닌 dict(result)를 반환
                    return result 
                
                # [수정] 프롬프트가 없는 경우
                return None

            # --- Case 2: 기타 ---
            print(f"[DEBUG ChatGPTAdapter] role={role}, name={name} => 프롬프트 추출 대상 아님")
            return None

        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
            return None

    # -------------------------------
    # 요청 변조 여부 및 변조 처리
    # -------------------------------
    def should_modify(self, host: str, content_type: str) -> bool:
        return "chatgpt.com" in host and "application/json" in content_type

    def modify_request_data(self, request_json: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        try:
            messages = request_json.get("messages", [])
            if not messages:
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})
            if author.get("role") != "user":
                return False, None

            content = last_message.get("content", {})
            parts = content.get("parts", [])

            # [수정] GPT-4o 등 parts가 dict일 경우도 처리
            if parts:
                if isinstance(parts[0], str):
                    request_data["messages"][-1]["content"]["parts"][0] = modified_prompt
                    modified_bytes = json.dumps(request_json, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes
                elif isinstance(parts[0], dict) and parts[0].get("content_type") == "text":
                    request_data["messages"][-1]["content"]["parts"][0]["content"] = modified_prompt
                    modified_bytes = json.dumps(request_json, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes

            # [수정] 'text' 필드만 있는 경우
            elif "text" in content:
                request_data["messages"][-1]["content"]["text"] = modified_prompt
                modified_bytes = json.dumps(request_json, ensure_ascii=False).encode("utf-8")
                return True, modified_bytes

            return False, None
        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None