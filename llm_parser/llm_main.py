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
from llm_parser.adapter.generic import GenericAdapter

# OCR 파일 처리 매니저 임포트
from ocr.file_manager import LLMFileManager


# -------------------------------
# LLM 프롬프트 추출 핸들러
class UnifiedLLMLogger:
    def __init__(self):
        # LLM 호스트 집합
        self.LLM_HOSTS = {
            "chatgpt.com", "claude.ai", "gemini.google.com",
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
        }

        # adapter 초기화
        self.adapters: Dict[str, LLMAdapter] = {}
        self.default_adapter = None
        self._init_adapters()

        # 파일 처리 매니저 초기화
        try:
            self.file_manager = LLMFileManager()
            print("[INFO] LLM 파일 처리 매니저 초기화 완료")
        except Exception as e:
            print(f"[ERROR] 파일 처리 매니저 초기화 실패: {e}")
            self.file_manager = None

    def _init_adapters(self):
        def inst(cls):
            return cls() if cls else None

        self.adapters["chatgpt.com"] = inst(ChatGPTAdapter)
        self.adapters["claude.ai"] = inst(ClaudeAdapter)
        self.adapters["gemini.google.com"] = inst(GeminiAdapter)
        self.adapters["chat.deepseek.com"] = inst(DeepSeekAdapter)
        self.adapters["groq.com"] = inst(GroqAdapter)
        self.adapters["api.openai.com"] = inst(GenericAdapter)
        self.adapters["api.anthropic.com"] = inst(ClaudeAdapter)
        self.adapters["generativelanguage.googleapis.com"] = inst(GeminiAdapter)
        self.adapters["aiplatform.googleapis.com"] = inst(GeminiAdapter)

        self.default_adapter = inst(GenericAdapter) or LLMAdapter()

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
    # 디스패처용 메서드: 프롬프트 추출만
    def extract_prompt_only(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트만 추출하여 반환 (로깅/서버 전송 없음)
        반환: {"prompt": str} 또는 None
        """
        try:

            # 1. 파일 업로드 요청 사전 차단 (핵심 변경사항)
            if self.file_manager and self.file_manager.is_file_upload_request(flow):
                print(f"[PRECHECK] 파일 업로드 요청 감지: {flow.request.pretty_host}{flow.request.path}")

                # 사전 검사 수행 (요청에서 파일 데이터 추출하여 OCR 검사)
                precheck_result = self.file_manager.process_upload_request_precheck(flow)

                if precheck_result:
                    print(f"[PRECHECK] 검사 결과: {precheck_result.get('reason', 'Unknown')}")

                    # 키워드 발견시 요청 자체를 차단
                    if precheck_result.get("blocked", False):
                        keyword = precheck_result.get("keyword", "알 수 없는 키워드")
                        context = precheck_result.get("context", "")

                        print(f"[PRECHECK] 파일 업로드 차단됨: {keyword}")

                        # 차단 응답 생성 (실제 서버로 요청 전송 안함!)
                        from security.block_handler import create_block_response
                        flow.response = create_block_response(keyword, context)
                        return  # 중요: 여기서 return하면 실제 서버로 요청이 전송되지 않음

                    else:
                        print(f"[PRECHECK] 파일 업로드 허용됨")
                        # 안전한 파일이면 원래 요청이 서버로 전송됨 (아무것도 안함)

                else:
                    print(f"[PRECHECK] 검사 실패 또는 지원하지 않는 요청")
                    # 검사 실패시 기본적으로 허용 (아무것도 안함)

                # 파일 업로드 요청은 여기서 처리 완료 (프롬프트 처리로 넘어가지 않음)
                return None



            # 2. 일반 LLM 프롬프트 요청 처리
            if not self.is_llm_request(flow) or flow.request.method != "POST":
                return None

            host = flow.request.pretty_host
            content_type = flow.request.headers.get("content-type", "").lower()
            request_data = None

            if "application/x-www-form-urlencoded" in content_type:
                request_data = flow.request.urlencoded_form
            elif "application/json" in content_type:
                body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(body)

            if not request_data:
                return None

            adapter = self.get_adapter(host)
            prompt = None
            if adapter:
                try:
                    prompt = adapter.extract_prompt(request_data, host)
                except Exception as e:
                    print(f"[WARN] prompt 추출 실패: {e}")
            else:
                print(f"[WARN] No adapter for {host}")

            if not prompt:
                return None

            # 프롬프트만 반환 (로깅/서버 전송은 디스패처에서 처리)
            return {"prompt": prompt}

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
            elif "application/json" in content_type:
                body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(body)

            if not request_data:
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



# mitmproxy addon 등록 (이제 dispatcher.py에서 클래스를 import해서 사용하므로 주석 처리)
# addons = [UnifiedLLMLogger()]
