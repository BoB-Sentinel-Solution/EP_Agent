#!/usr/bin/env python3
import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime
import threading
from mitmproxy import http
from typing import Dict, Any
import asyncio
import time
import os

import requests

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

# =========================================================
# 서버 전송 주소 (하드코딩) 수정: 클라우드 IP 사용
SENTINEL_SERVER_URL = "https://158.180.72.194/logs"
# 자가서명 TLS 테스트 시만 False. 운영에서는 반드시 True 유지.
REQUESTS_VERIFY_TLS = False
# =========================================================

def get_control_decision(host: str, prompt: str) -> dict:
    """
    서버로 제어 결정을 요청.
    - 반드시 POST /logs (JSON)
    - 프록시 환경변수 무시(trust_env=False)로 회사/시스템 프록시 우회
    - (연결,읽기) 타임아웃 분리
    """
    try:
        print(f"FastAPI 서버에 요청 중... ({host}) -> {SENTINEL_SERVER_URL}")

        payload = {
            'time': datetime.now().isoformat(),
            'host': host,
            'prompt': prompt,
            'interface': 'llm'
        }

        # 프록시 환경변수 무시 (회사/시스템 프록시로 빠지는 문제 차단)
        session = requests.Session()
        session.trust_env = False   # HTTPS_PROXY/HTTP_PROXY 무시
        # 혹시 코드 내부에서 proxies가 설정될 여지를 완전히 제거
        session.proxies = {}

        # (연결,읽기) 타임아웃 분리: 연결 3초, 읽기 12초
        timeout = (3.0, 12.0)

        # 반드시 POST + JSON
        response = session.post(
            SENTINEL_SERVER_URL,
            json=payload,
            timeout=timeout,
            verify=REQUESTS_VERIFY_TLS
        )

        if response.status_code == 200:
            decision = response.json()
            print(f"FastAPI 서버 응답: {decision}")
            return decision
        else:
            print(f"FastAPI 서버 오류: HTTP {response.status_code} {response.text[:200]}")
            return {'action': 'allow'}

    except requests.exceptions.ProxyError as e:
        print(f"[PROXY] 프록시 오류(trust_env=False로 무시 중): {e}")
        return {'action': 'allow'}
    except requests.exceptions.SSLError as e:
        print(f"[TLS] 인증서 오류: {e} (verify={REQUESTS_VERIFY_TLS})")
        return {'action': 'allow'}
    except requests.exceptions.ConnectTimeout:
        print("[NET] 연결 타임아웃(서버에 TCP 연결 실패)")
        return {'action': 'allow'}
    except requests.exceptions.ReadTimeout:
        print("[NET] 읽기 타임아웃(서버 응답 지연)")
        return {'action': 'allow'}
    except requests.exceptions.RequestException as e:
        print(f"[NET] 요청 실패: {repr(e)}")
        return {'action': 'allow'}


# -------------------------------
# 통합 LLM Logger
class UnifiedLLMLogger:
    def __init__(self):
        self.base_dir = Path.home() / ".llm_proxy"
        self.json_log_file = self.base_dir / "llm_requests.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)

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

    def save_log(self, log_entry: Dict[str, Any]):
        try:
            logs = []
            if self.json_log_file.exists():
                try:
                    content = self.json_log_file.read_text(encoding="utf-8").strip()
                    if content:
                        logs = json.loads(content)
                except (json.JSONDecodeError, OSError):
                    logs = []
            logs.append(log_entry)
            if len(logs) > 100:
                logs = logs[-100:]
            self.json_log_file.write_text(json.dumps(logs, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            print(f"[ERROR] 로그 저장 실패: {e}")



    # -------------------------------
    # mitmproxy hook: 요청(Request) 처리
    def request(self, flow: http.HTTPFlow):
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
                return



            # 2. 일반 LLM 프롬프트 요청 처리
            if not self.is_llm_request(flow) or flow.request.method != "POST":
                return

            host = flow.request.pretty_host
            content_type = flow.request.headers.get("content-type", "").lower()
            request_data = None

            if "application/x-www-form-urlencoded" in content_type:
                request_data = flow.request.urlencoded_form
            elif "application/json" in content_type:
                body = self.safe_decode_content(flow.request.content)
                request_data = self.parse_json_safely(body)

            if not request_data:
                return

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
                return

            print(f"[LOG] {host} - {prompt[:80] if len(prompt) > 80 else prompt}")

            # -------------------------------
            print("FastAPI 서버로 전송, 홀딩 시작...")
            start_time = datetime.now()

            decision = get_control_decision(host, prompt)

            end_time = datetime.now()
            elapsed = (end_time - start_time).total_seconds()
            print(f"홀딩 완료! 소요시간: {elapsed:.1f}초")

            # 변조된 프롬프트가 있으면 대체
            modified_prompt = decision.get('modified_prompt')
            if modified_prompt:
                print(f"[MODIFY] {prompt[:30]}... -> {modified_prompt[:50]}...")

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

            # 로그 저장
            log_entry = {
                "time": datetime.now().isoformat(),
                "host": host,
                "prompt": prompt,
                "modified_prompt": modified_prompt if modified_prompt else prompt,
                "holding_time": elapsed,
                "interface": "llm"
            }
            self.save_log(log_entry)

            print("프롬프트 변조 완료, 요청 허용")

        except Exception as e:
            print(f"[ERROR] request hook 실패: {e}")



# mitmproxy addon 등록
addons = [UnifiedLLMLogger()]
