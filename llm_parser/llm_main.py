#!/usr/bin/env python3
"""
LLM 트래픽 파서 - 텍스트 프롬프트와 파일 다운로드 통합 처리
리팩토링 포인트:
 - adapter 모듈을 모듈 레벨에서 직접 임포트하지 않고 런타임에 임포트하여 순환 import 방지
 - httpx/aiofiles가 없을 경우 동기 requests 방식으로 폴백
 - 중복 addons 제거
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Optional, Dict, Any, List
import re
import asyncio

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_parser.common.utils import LLMAdapter 
from llm_parser.adapter.chat_gpt import ChatGPTAdapter
from llm_parser.adapter.claude import ClaudeAdapter
from llm_parser.adapter.gemini import GeminiAdapter
from llm_parser.adapter.generic import GenericAdapter

# -------------------------------
# 통합 LLM Logger
# -------------------------------
class UnifiedLLMLogger:
    def __init__(self):
        # 파일/폴더 준비
        self.base_dir = Path.home() / ".llm_proxy"
        self.json_log_file = self.base_dir / "llm_requests.json"
        self.download_dir = self.base_dir / "downloads"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)

        # LLM 관련 호스트 집합 (부분 문자열 매칭에 사용)
        self.LLM_HOSTS = {
            "api.openai.com", "chatgpt.com", "api.anthropic.com", "claude.ai",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "gemini.google.com", "api.groq.com", "api.cohere.ai", "api.deepseek.com"
        }

        # adapters 매핑은 런타임에 임포트하여 인스턴스화 (순환 import 방지)
        self.adapters: Dict[str, LLMAdapter] = {}
        self.default_adapter = None
        self._init_adapters()



    def _init_adapters(self):

        def inst(cls):
                # 클래스가 None이 아니면 인스턴스 생성, 아니면 None 반환
                return cls() if cls else None

        self.adapters["chatgpt.com"] = inst(ChatGPTAdapter)
        self.adapters["api.openai.com"] = inst(GenericAdapter)
        self.adapters["api.anthropic.com"] = inst(ClaudeAdapter)
        self.adapters["claude.ai"] = inst(ClaudeAdapter)
        self.adapters["gemini.google.com"] = inst(GeminiAdapter)
        self.adapters["generativelanguage.googleapis.com"] = inst(GeminiAdapter)
        self.adapters["aiplatform.googleapis.com"] = inst(GeminiAdapter)

        # GenericAdapter가 있으면 기본값으로, 없으면 빈 기본 어댑터 사용
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
            return content.decode('utf-8', errors='replace')
        except Exception:
            return f"[BINARY_CONTENT: {len(content)} bytes]"

    def parse_json_safely(self, content: str) -> dict:
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}


    # 로그 저장 로직 추가 (기존 코드에 없어서 추가했습니다)
    def save_log(self, log_entry: Dict[str, Any]):
        try:
            logs = []
            if self.json_log_file.exists():
                try:
                    content = self.json_log_file.read_text(encoding="utf-8").strip()
                    if content:
                        logs = json.loads(content)
                except (json.JSONDecodeError, OSError):
                    logs = [] # 파일이 손상되었으면 새로 시작
            
            logs.append(log_entry)
            
            # 최근 100개 로그만 유지
            if len(logs) > 100:
                logs = logs[-100:]

            self.json_log_file.write_text(json.dumps(logs, indent=2, ensure_ascii=False), encoding='utf-8')
        except Exception as e:
            print(f"[ERROR] 로그 저장 실패: {e}")

    # mitmproxy hook: 요청(Request) 처리 (동기 호출)
    def request(self, flow: http.HTTPFlow):
        try:
            if not self.is_llm_request(flow) or flow.request.method != 'POST':
                return
            host = flow.request.pretty_host
            request_body = self.safe_decode_content(flow.request.content)
            request_json = self.parse_json_safely(request_body)
            if not request_json:
                return
            adapter = self.get_adapter(host)
            # adapter가 None이면 건너뛰기
            if not adapter:
                return
            prompt = None
            attachments = []
            try:
                prompt = adapter.extract_prompt(request_json, host)
                attachments = adapter.extract_attachments(request_json, host)
            except Exception as e:
                print(f"[WARN] adapter.extract_* 호출 중 예외: {e}")

            if prompt or attachments:
                log_entry = {
                    "time": datetime.now().isoformat(),
                    "host": host,
                    "prompt": prompt or "",
                    "attachments": attachments,
                    "interface": "llm"
                }
                self.save_log(log_entry)
                print(f"[LOG] {host} - {(prompt[:80] if prompt else '[첨부파일]')}...")
        except Exception as e:
            print(f"[ERROR] request hook 실패: {e}")

    # mitmproxy hook: 응답(Response) 처리 (동기 호출이지만 내부에서 비동기 작업 생성 가능)
    def response(self, flow: http.HTTPFlow):
        try:
            if not self.is_llm_request(flow):
                return
            adapter = self.get_adapter(flow.request.pretty_host)
            if not adapter:
                return
            try:
                if adapter.is_file_download_request(flow):
                    file_info = adapter.extract_file_info(flow)
                    if file_info:
                        cert_path = Path.home() / ".llm_proxy" / ".mitmproxy" / "mitmproxy-ca-cert.pem"
                        if not cert_path.exists():
                            print(f"[ERROR] mitmproxy CA 인증서 파일을 찾을 수 없습니다: {cert_path}")
                            return
                        # 백그라운드에서 다운로드 수행 (비동기 이벤트 루프를 사용)
                        try:
                            loop = asyncio.get_event_loop()
                            # if loop is running, create_task; else start new task via run_until_complete
                            if loop.is_running():
                                loop.create_task(self.download_file(file_info, cert_path))
                            else:
                                # 이벤트 루프가 없으면 새 루프에서 실행 (blocking)
                                loop.run_until_complete(self.download_file(file_info, cert_path))
                        except Exception as e:
                            # 마지막 폴백: 동기 다운로드 시도
                            print(f"[WARN] 비동기 다운로드 스케줄링 실패: {e}. 동기 폴백으로 시도합니다.")
                            self._sync_download_with_requests(file_info, cert_path)
            except Exception as e:
                print(f"[ERROR] adapter 파일 처리 중 예외: {e}")
        except Exception as e:
            print(f"[ERROR] response hook 실패: {e}")


# mitmproxy 애드온 등록 (하나만)
addons = [UnifiedLLMLogger()]
