#!/usr/bin/env python3
"""
LLM 프롬프트 추출 핸들러
- 디스패처에서 호출되어 프롬프트 추출과 패킷 변조만 담당
- 로깅과 서버 전송은 디스패처에서 처리
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


# -------------------------------
# LLM 프롬프트 추출 핸들러
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
        self.adapters["api.openai.com"] = inst(ChatGPTAdapter)
        self.adapters["api.anthropic.com"] = inst(ClaudeAdapter)
        self.adapters["generativelanguage.googleapis.com"] = inst(GeminiAdapter)
        self.adapters["aiplatform.googleapis.com"] = inst(GeminiAdapter)

        self.default_adapter = LLMAdapter()

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



    # -------------------------------
    # 디스패처용 메서드: 프롬프트 + 파일 정보 추출
    def extract_prompt_only(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트 및 파일 정보 추출하여 반환
        반환: {"prompt": str, "attachment": {...}} 또는 None
        """
        try:
            host = flow.request.pretty_host

            # 1. 파일 업로드 요청 처리 (PUT 요청 등)
            if self.is_llm_request(flow):
                adapter = self.get_adapter(host)
                print(f"[DEBUG llm_main] 어댑터 확인: {adapter.__class__.__name__ if adapter else 'None'}")
                if adapter and hasattr(adapter, 'extract_file_from_upload_request'):
                    try:
                        file_info = adapter.extract_file_from_upload_request(flow)
                        print(f"[DEBUG llm_main] 파일 추출 결과: {file_info is not None}")
                        if file_info:
                            print(f"[DEBUG llm_main] file_info 키들: {list(file_info.keys())}")
                            print(f"[DEBUG llm_main] file_id 값: {file_info.get('file_id')}")
                            print(f"[DEBUG llm_main] attachment 존재: {file_info.get('attachment') is not None}")
                            # 파일 업로드 요청: file_id + attachment 반환
                            # ChatGPT/Claude 모두 {"file_id": str, "attachment": {...}} 형태
                            return file_info
                    except Exception as e:
                        print(f"[WARN] 파일 추출 시도 중 오류: {e}")

            # 2. 프롬프트 요청 처리 (POST 요청)
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

             #여기서부터
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

            # Claude의 경우 attachments에서 extracted_content 확인 (CSV 등)
            attachment_data = {"format": None, "data": None}
            if "claude.ai" in host and request_data:
                attachments = request_data.get("attachments", [])
                if attachments:
                    for att in attachments:
                        extracted_content = att.get("extracted_content")
                        if extracted_content:
                            file_type = att.get("file_type", "unknown")
                            file_name = att.get("file_name", "unknown")
                            file_size = att.get("file_size", 0)

                            # 텍스트를 base64로 인코딩
                            import base64
                            encoded_data = base64.b64encode(extracted_content.encode('utf-8')).decode('utf-8')

                            file_format = file_type.split("/")[-1] if "/" in file_type else file_type
                            attachment_data = {
                                "format": file_format,
                                "data": encoded_data
                            }
                            print(f"[INFO llm_main] CSV/텍스트 파일 프롬프트와 함께 추출: {file_name} ({file_format}, {file_size} bytes)")
                            break  # 첫 번째 파일만 처리

            # 프롬프트 + attachment + 원본 데이터 반환 (변조용)
            result = {
                "prompt": prompt_text,
                "attachment": attachment_data,
                "context": {
                    "request_data": request_data,  # 원본 request_data 저장
                    "content_type": content_type,
                    "host": host
                }
            }

            # ChatGPTAdapter가 interface를 제공한 경우 추가
            if interface_from_adapter:
                result["interface"] = interface_from_adapter

            return result

        except Exception as e:
            print(f"[ERROR] extract_prompt_only 실패: {e}")
            return None

    def modify_request(self, flow: http.HTTPFlow, modified_prompt: str, extracted_data: Dict[str, Any]):
        """
        디스패처용 메서드: 패킷 변조만 수행

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_prompt: 변조할 프롬프트
            extracted_data: extract_prompt_only()에서 반환한 데이터 (context 포함)
        """
        try:
            # context에서 저장된 원본 데이터 가져오기
            context = extracted_data.get("context", {})
            request_data = context.get("request_data")
            content_type = context.get("content_type", "")
            host = context.get("host", flow.request.pretty_host)

            if not request_data:
                print("[WARN] 변조 실패: context에 request_data 없음")
                return

            adapter = self.get_adapter(host)

            if adapter and adapter.should_modify(host, content_type):
                try:
                    print(f"[DEBUG] modify_request 시작 - host={host}, content_type={content_type}")
                    print(f"[DEBUG] request_data keys: {list(request_data.keys())}")

                    success, modified_content = adapter.modify_request_data(request_data, modified_prompt, host)

                    print(f"[DEBUG] modify_request_data 결과 - success={success}, content_length={len(modified_content) if modified_content else 'None'}")

                    if success and modified_content:
                        flow.request.content = modified_content
                        flow.request.headers["Content-Length"] = str(len(modified_content))
                        print(f"[LLM] 패킷 변조 완료: {len(modified_content)} bytes")
                    else:
                        print(f"[LLM] 패킷 변조 실패: {host}")
                        print(f"[DEBUG] 패킷 변조 실패 상세 - success={success}, modified_content_type={type(modified_content)}")
                        print(f"[DEBUG] 마지막 메시지 구조: {request_data.get('messages', [])[-1]}")
                except Exception as e:
                    print(f"[LLM MODIFY] error: {e}")


        except Exception as e:
            print(f"[ERROR] LLM modify_request 실패: {e}")


