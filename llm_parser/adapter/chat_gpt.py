# chat_gpt.py
import os
import json
import logging
from typing import Optional, Dict, Any, Tuple
from mitmproxy import http
from datetime import datetime
from llm_parser.common.utils import LLMAdapter, FileUtils

UNIFIED_LOG_PATH = "./unified_request.json"
LAST_USER_LOG_PATH = "./last_user_log.json"

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

    def _save_last_user_log(self, data: dict):
        """가장 최근 user role 로그를 별도로 저장"""
        try:
            with open(LAST_USER_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ERROR] last_user_log.json 저장 실패: {e}")

    def _load_last_user_log(self) -> Optional[dict]:
        """이전 user role 로그 불러오기"""
        try:
            if os.path.exists(LAST_USER_LOG_PATH):
                with open(LAST_USER_LOG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[WARN] last_user_log.json 불러오기 실패: {e}")
        return None

    # -------------------------------
    # 핵심: ChatGPT 전용 프롬프트 추출
    # -------------------------------
    def extract_prompt(self, request_json: dict, host: str, path: str = None) -> Optional[str]:
        try:
            messages = request_json.get("messages", [])
            if not isinstance(messages, list) or not messages:
                return None

            last_message = messages[-1]
            author = last_message.get("author", {})
            role = author.get("role")
            name = author.get("name")

            # --- 경로 기반 MCP 체크 (ChatGPT 전용) ---
            if path:
                # /backend-api/conversation: role 확인 없이 무조건 MCP
                if "/backend-api/conversation" in path and "/f/conversation" not in path:
                    print("[DEBUG ChatGPTAdapter] /backend-api/conversation 경로 감지 — MCP 로깅 처리")
                    self.handle_tool_call()
                    return None

                # /backend-api/f/conversation: role이 tool일 때만 MCP
                if "/backend-api/f/conversation" in path and role == "tool":
                    print("[DEBUG ChatGPTAdapter] /backend-api/f/conversation + tool role 감지 — MCP 로깅 처리")
                    self.handle_tool_call()
                    return None

            # --- Case 1: user role ---
            if role == "user":
                content = last_message.get("content", {})
                parts = content.get("parts", [])
                text = content.get("text")

                if parts and isinstance(parts, list):
                    text_parts_list = []
                    for part in parts:
                        if isinstance(part, str):
                            text_parts_list.append(part)
                        elif isinstance(part, dict) and part.get("content_type") == "text":
                            text_parts_list.append(part.get("content", ""))
                    if text_parts_list:
                        full_prompt = " ".join(text_parts_list)[:1000]
                        print(f"[DEBUG ChatGPTAdapter] user role 프롬프트 추출: {full_prompt[:50]}...")
                        return full_prompt

                if text and isinstance(text, str):
                    print(f"[DEBUG ChatGPTAdapter] user role text 추출: {text[:50]}...")
                    return text[:1000]
                return None

            # --- Case 2: tool role + api_tool.call_tool ---
            elif role == "tool" and name == "api_tool.call_tool":
                print("[DEBUG ChatGPTAdapter] tool role(api_tool.call_tool) 패킷 감지 — MCP 로깅 처리 시작")
                self.handle_tool_call()
                return None

            # --- Case 3: 기타 ---
            print(f"[DEBUG ChatGPTAdapter] role={role}, name={name} => 프롬프트 추출 대상 아님")
            return None

        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
            return None

    # -------------------------------
    # MCP 변환 처리
    # -------------------------------
    def handle_tool_call(self):
        """최근 user 로그(A)를 불러와서 interface를 'mcp'로 변경 후 재로깅"""
        prev_log = self._load_last_user_log()
        if not prev_log:
            print("[WARN] 이전 user 로그가 없어 MCP 변환 불가.")
            return
        prev_log["interface"] = "mcp"
        prev_log["timestamp"] = datetime.now().isoformat()
        self._save_unified_log(prev_log)
        print("[INFO] MCP 변환 로그 기록 완료 (interface='mcp')")

    # -------------------------------
    # 요청 변조 여부 및 변조 처리
    # -------------------------------
    def should_modify(self, host: str, content_type: str) -> bool:
        return "chatgpt.com" in host and "application/json" in content_type

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        try:
            messages = request_data.get("messages", [])
            if not messages:
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})
            if author.get("role") != "user":
                return False, None

            content = last_message.get("content", {})
            parts = content.get("parts", [])
            if parts and isinstance(parts[0], str):
                request_data["messages"][-1]["content"]["parts"][0] = modified_prompt
                modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                return True, modified_bytes
            return False, None
        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None
