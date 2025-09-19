#!/usr/bin/env python3
"""
LLM 트래픽 파서 - 텍스트 프롬프트와 파일 다운로드 통합 처리

"""
import json
import sys
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Optional, Dict, Any, List
import logging

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_parser.common.utils import LLMAdapter 
from llm_parser.adapter.chat_gpt import ChatGPTAdapter
from llm_parser.adapter.claude import ClaudeAdapter
from llm_parser.adapter.gemini import GeminiAdapter
from llm_parser.adapter.deepseek import DeepSeekAdapter
from llm_parser.adapter.groq import GroqAdapter

from llm_parser.adapter.generic import GenericAdapter

from ocr.ocr_engine import OCREngine
from security import KeywordManager, ImageScanner, create_block_response

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

        # # 후처리를 위한 폴더 경로 정의
        # self.processed_dir = self.base_dir / "processed"
        # self.failed_dir = self.base_dir / "failed"
        # # 폴더가 없으면 생성
        # self.processed_dir.mkdir(exist_ok=True)
        # self.failed_dir.mkdir(exist_ok=True)


        # ocr 엔진 초기화 및 키워드 차단 db 매니저 초기화
        # self.keyword_manager = KeywordManager()
        # self.image_scanner = ImageScanner()
        # self.ocr_engine = OCREngine(['ko', 'en'])


        # LLM 관련 호스트 집합 (부분 문자열 매칭에 사용)
        self.LLM_HOSTS = {
            "chatgpt.com", "claude.ai", "gemini.google.com", 
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            
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
        self.adapters["claude.ai"] = inst(ClaudeAdapter)
        self.adapters["gemini.google.com"] = inst(GeminiAdapter)
        self.adapters["chat.deepseek.com"] = inst(DeepSeekAdapter)
        self.adapters["groq.com"] = inst(GroqAdapter)

        self.adapters["api.openai.com"] = inst(GenericAdapter)
        self.adapters["api.anthropic.com"] = inst(ClaudeAdapter)
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


    # 로그 저장 로직 
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
  
            request_data = None
            content_type = flow.request.headers.get("content-type", "").lower()

            # 1. Content-Type에 따라 파싱 방식을 결정합니다.
            if "application/x-www-form-urlencoded" in content_type:
                # Gemini 웹 트래픽과 같은 Form 데이터는 urlencoded_form으로 파싱합니다.
                request_data = flow.request.urlencoded_form
            elif "application/json" in content_type:
                # ChatGPT, Claude API와 같은 일반적인 경우는 JSON으로 파싱합니다.
                request_body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(request_body)

            # 파싱된 데이터가 없으면 더 이상 진행하지 않습니다.
            if not request_data:
                return

            adapter = self.get_adapter(host)
            # adapter가 None이면 건너뛰기
            if not adapter:
                return
            prompt = None
            attachments = []
            try:
                prompt = adapter.extract_prompt(request_data, host)
            except Exception as e:
                print(f"[WARN] adapter.extract_* 호출 중 예외: {e}")

            if prompt or attachments:
                log_entry = {
                    "time": datetime.now().isoformat(),
                    "host": host,
                    "prompt": prompt or "",
                    "interface": "llm"
                }
                self.save_log(log_entry)
                print(f"[LOG] {host} - {(prompt[:80] if prompt else '[첨부파일]')}...")
        except Exception as e:
            print(f"[ERROR] request hook 실패: {e}")



    # # mitmproxy hook: 응답(Response) 처리
    # async def response(self, flow: http.HTTPFlow):
    #     """
    #     mitmproxy의 비동기 이벤트 훅입니다.
    #     파일 다운로드 요청을 감지하고 백그라운드에서 다운로드를 수행합니다.
    #     """

    #     adapter = self.get_adapter(flow.request.pretty_host)
    #     if not adapter:
    #         return

    #     # 2. 어댑터가 파일 다운로드 요청이라고 판단하는 경우에만 로직을 실행합니다.
    #     if not adapter.is_file_download_request(flow):
    #         return

    #     try:
    #         file_info = adapter.extract_file_info(flow)
    #         if not file_info:
    #             return

    #         cert_path = self.base_dir / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    #         if not cert_path.exists():
    #             print(f"[ERROR] mitmproxy CA 인증서 파일을 찾을 수 없습니다: {cert_path}")
    #             return

    #         print(f"[INFO] 파일 다운로드 시작: {file_info.get('file_name', 'unknown')}")

    #         # 3. await를 사용하여 download_file 코루틴을 직접 실행합니다.
    #         from ocr.downloader import download_file 
    #         result = await download_file(file_info, self.download_dir, cert_path)

    #         # 4. 다운로드 결과를 확인하고 로그를 남깁니다.
    #         if result:
    #             print(f"[SUCCESS] 파일 다운로드 완료: {result}")
    #             # 여기에 OCR 등 후속 작업을 연결할 수 있습니다.
    #         else:
    #             print(f"[FAILURE] 파일 다운로드에 실패했습니다. 이전 로그를 확인하세요.")

    #     except Exception as e:
    #         import traceback
    #         print(f"[ERROR] response hook 처리 중 예외 발생: {e}\n{traceback.format_exc()}")
        
# mitmproxy 애드온 등록 
addons = [UnifiedLLMLogger()]
