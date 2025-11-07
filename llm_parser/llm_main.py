#!/usr/bin/env python3
"""
LLM 프롬프트 추출 핸들러
- 디스패처에서 호출되어 프롬프트 추출과 패킷 변조만 담당
- 로깅과 서버 전송은 디스패처에서 처리
- tool 콜(api_tool.call_tool) 이벤트를 상위로 올려 RequestHandler에서 처리되게 함
"""
import json
import sys
import os
from pathlib import Path
from mitmproxy import http
from typing import Dict, Any, Optional

# Windows 콘솔 UTF-8 출력 강제 설정
if sys.platform == "win32":
    os.system("chcp 65001 > nul")
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from llm_parser.common.utils import LLMAdapter
from llm_parser.adapter.chat_gpt import ChatGPTAdapter
from llm_parser.adapter.claude import ClaudeAdapter
from llm_parser.adapter.gemini import GeminiAdapter
from llm_parser.adapter.deepseek import DeepSeekAdapter
from llm_parser.adapter.groq import GroqAdapter


class UnifiedLLMLogger:
    def __init__(self):
        # LLM 호스트 집합
        self.LLM_HOSTS = {
            "chatgpt.com", "oaiusercontent.com",  # ChatGPT + 파일 업로드
            "claude.ai", "gemini.google.com",
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
        }

        # adapter 초기화
        self.adapters: Dict[str, LLMAdapter] = {}
        self.default_adapter = None
        self._init_adapters()

    def _init_adapters(self):
        def inst(cls):
            return cls() if cls else None

        self.adapters["chatgpt.com"] = inst(ChatGPTAdapter)
        self.adapters["oaiusercontent.com"] = inst(ChatGPTAdapter)  # ChatGPT 파일 업로드
        self.adapters["claude.ai"] = inst(ClaudeAdapter)
        self.adapters["gemini.google.com"] = inst(GeminiAdapter)
        self.adapters["chat.deepseek.com"] = inst(DeepSeekAdapter)
        self.adapters["groq.com"] = inst(GroqAdapter)
        self.adapters["api.anthropic.com"] = inst(ClaudeAdapter)
        self.adapters["generativelanguage.googleapis.com"] = inst(GeminiAdapter)
        self.adapters["aiplatform.googleapis.com"] = inst(GeminiAdapter)

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        return any(host in flow.request.pretty_host for host in self.LLM_HOSTS)

    def get_adapter(self, host: str) -> LLMAdapter:
        for adapter_host, adapter in self.adapters.items():
            if adapter is None:
                continue
            if adapter_host in host:
                return adapter
        return self.default_adapter

    def safe_decode_content(self, content: bytes) -> str:
        if not content:
            return ""
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return f"[BINARY_CONTENT: {len(content)} bytes]"

    def parse_json_safely(self, content: str) -> dict:
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}

    def extract_prompt_only(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트 및 파일 정보 추출하여 반환
        반환:
          - {"prompt": str, "attachment": {...}, "meta": {...}}
          - 또는 {"event": "tool_call", "meta": {...}}
          - 또는 None
        """
        try:
            host = flow.request.pretty_host

            # ChatGPT GET /backend-api/conversation 요청 특별 처리 (MCP)
            #if "chatgpt.com" in host and flow.request.method == "GET" and "/backend-api/conversation" in flow.request.path:
            #    print(f"[DEBUG] ChatGPT GET /backend-api/conversation 감지 — MCP 로깅")
            #    return {"event": "tool_call", "meta": {"path": flow.request.path}}

            # 프롬프트 요청 처리 (POST 요청)
            if not self.is_llm_request(flow) or flow.request.method != "POST":
                return None

            content_type = flow.request.headers.get("content-type", "").lower()
            request_data = None

            if "application/x-www-form-urlencoded" in content_type:
                request_data = flow.request.urlencoded_form
                # MultiDictView를 dict로 변환 (Gemini 파싱을 위해 필수)
                if request_data and not isinstance(request_data, dict):
                    request_data = dict(request_data)
            elif "application/json" in content_type:
                body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(body)

            if not isinstance(request_data, dict) or not request_data:
                return None

            # ===== meta 추출 (role/name/conversation_id 등) =====
            meta: Dict[str, Any] = {}
            msgs = request_data.get("messages", [])
            if isinstance(msgs, list) and msgs:
                last = msgs[-1]
                author = last.get("author", {}) if isinstance(last, dict) else {}
                meta["role"] = author.get("role")
                meta["name"] = author.get("name")
            meta["conversation_id"] = request_data.get("conversation_id")
            meta["parent_message_id"] = request_data.get("parent_message_id")

            # tool 콜 이벤트면 prompt 없이 이벤트만 반환
            if meta.get("role") == "tool" and meta.get("name") == "api_tool.call_tool":
                return {"event": "tool_call", "meta": meta}

            # ===== 프롬프트 추출 =====
            adapter = self.get_adapter(host)
            prompt = None

            if adapter:
                try:
                    # path 인자 전달 (ChatGPTAdapter만 사용)
                    prompt = adapter.extract_prompt(request_data, host, path=flow.request.path)
                except TypeError:
                    # path 인자를 받지 않는 adapter (하위 호환성)
                    prompt = adapter.extract_prompt(request_data, host)
                except Exception as e:
                    print(f"[WARN] prompt 추출 실패: {e}")
            else:
                print(f"[WARN] No adapter for {host}")

            if not prompt:
                return None

            # ChatGPTAdapter가 딕셔너리를 반환하는 경우 처리
            prompt_text = None
            attachment_data = {"format": None, "data": None}
            interface_from_adapter = None

            if isinstance(prompt, dict):
                # ChatGPTAdapter 형식: {"prompt": str, "attachment": dict, "interface": str}
                prompt_text = prompt.get("prompt")
                attachment_data = prompt.get("attachment", {"format": None, "data": None})
                interface_from_adapter = prompt.get("interface")
            elif isinstance(prompt, str):
                # 기존 어댑터 형식: 문자열만 반환
                prompt_text = prompt
            else:
                print(f"[WARN] 예상치 못한 prompt 타입: {type(prompt)}")
                return None

            if not prompt_text:
                return None

            result = {
                "prompt": prompt_text,
                "attachment": attachment_data,
                "meta": meta,
            }

            # ChatGPTAdapter가 interface를 제공한 경우 추가
            if interface_from_adapter:
                result["interface"] = interface_from_adapter

            return result

        except Exception as e:
            print(f"[ERROR] extract_prompt_only 실패: {e}")
            return None

    def modify_request(self, flow: http.HTTPFlow, modified_prompt: str):
        """
        디스패처용 메서드: 패킷 변조만 수행
        """
        try:
            host = flow.request.pretty_host
            content_type = flow.request.headers.get("content-type", "").lower()
            request_data = None

            if "application/x-www-form-urlencoded" in content_type:
                request_data = flow.request.urlencoded_form
                # MultiDictView를 dict로 변환 (Gemini 파싱을 위해 필수)
                if request_data and not isinstance(request_data, dict):
                    request_data = dict(request_data)              
            elif "application/json" in content_type:
                body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(body)

            if not isinstance(request_data, dict) or not request_data:
                print("[WARN] 변조 실패: request_data 없음")
                return

            adapter = self.get_adapter(host)

            # 어댑터 기반 패킷 변조
            if adapter and adapter.should_modify(host, content_type):
                try:
                    success, modified_content = adapter.modify_request_data(request_data, modified_prompt, host)
                    if success and modified_content:
                        flow.request.content = modified_content
                        flow.request.headers["Content-Length"] = str(len(modified_content))
                        print(f"패킷 변조 완료: {len(modified_content)} bytes")
                    else:
                        print(f"패킷 변조 실패: {host}")
                except Exception as e:
                    print(f"[MODIFY] error: {e}")
            else:
                print(f"변조 지원하지 않음: {host}")

        except Exception as e:
            print(f"[ERROR] modify_request 실패: {e}")