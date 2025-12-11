#!/usr/bin/env python3
"""
Sentinel Proxy Engine - mitmproxy addon
기존 dispatcher.py의 모든 기능을 유지하면서 mitmproxy addon 구조로 재구성
"""
import socket
from pathlib import Path
from datetime import datetime
from mitmproxy import http, ctx
from typing import Set

# 네트워크 유틸리티
from utils.network_utils import get_public_ip, get_private_ip

# 기존 핸들러 임포트
from llm_parser.llm_main import UnifiedLLMLogger
from app_parser.app_main import UnifiedAppLogger

# 분리된 모듈 임포트
from proxy_dispatcher.server_client import ServerClient
from proxy_dispatcher.cache_manager import FileCacheManager
from proxy_dispatcher.log_manager import LogManager
from proxy_dispatcher.request_handler import RequestHandler
from proxy_dispatcher.response_handler import ResponseHandler

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)

# =========================================================
# 설정 (하드코딩 → TODO: 설정 파일로 분리)
# =========================================================
SENTINEL_SERVER_URL = "https://bobsentinel.site/api/logs"
REQUESTS_VERIFY_TLS = False


class SentinelProxyAddon:
    """통합 디스패처 - Orchestrator"""

    def __init__(self):
        """디스패처 초기화"""
        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 시작...")
        print("="*60)

        # ===== 호스트 정의 =====
        self.LLM_HOSTS: Set[str] = {
            "chatgpt.com", "oaiusercontent.com",  # ChatGPT + 파일 업로드
            "claude.ai", "gemini.google.com", "push.clients6.google.com",  # Gemini + 파일 업로드
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "api.openai.com", "api.anthropic.com"
        }

        self.APP_HOSTS: Set[str] = {
           

            # VSCode Copilot
            "api.githubcopilot.com",
            "api.individual.githubcopilot.com",
            "copilot-proxy.githubusercontent.com",
            "copilot", "githubusercontent.com", "github.com"
        }

        # ===== 디렉터리 설정 =====
        self.base_dir = Path.home() / ".llm_proxy"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        print(f"[INIT] 로그 디렉터리: {self.base_dir}")

        # ===== 시스템 정보 캐싱 =====
        self.hostname = socket.gethostname()
        print(f"[INIT] 호스트명: {self.hostname}")
        self.public_ip = get_public_ip()
        print(f"[INIT] 공인 IP: {self.public_ip}")
        self.private_ip = get_private_ip()
        print(f"[INIT] 사설 IP: {self.private_ip}")

        # ===== LLM/App 핸들러 초기화 =====
        print("\n[INIT] LLM 핸들러 초기화 중...")
        try:
            self.llm_handler = UnifiedLLMLogger()
            print("[INIT] ✓ LLM 핸들러 초기화 완료")
        except Exception as e:
            print(f"[INIT] ✗ LLM 핸들러 초기화 실패: {e}")
            import traceback
            traceback.print_exc()
            raise

        print("\n[INIT] App/MCP 핸들러 초기화 중...")
        try:
            self.app_handler = UnifiedAppLogger()
            print("[INIT] ✓ App/MCP 핸들러 초기화 완료")
        except Exception as e:
            print(f"[INIT] ✗ App/MCP 핸들러 초기화 실패: {e}")
            import traceback
            traceback.print_exc()
            raise

        # ===== 모듈 초기화 =====
        print("\n[INIT] 서브 모듈 초기화 중...")

        # 서버 클라이언트
        self.server_client = ServerClient(
            server_url=SENTINEL_SERVER_URL,
            verify_tls=REQUESTS_VERIFY_TLS
        )
        print(f"[INIT] ✓ 서버 클라이언트 초기화: {SENTINEL_SERVER_URL}")

        # 로그 매니저
        self.log_manager = LogManager(
            log_file_path=self.base_dir / "unified_requests.json",
            max_entries=100
        )
        print("[INIT] ✓ 로그 매니저 초기화")

        # 캐시 매니저 (ChatGPT POST/PUT 매칭, file_id 매핑)
        self.cache_manager = FileCacheManager()
        print(f"[INIT] ✓ 캐시 매니저 초기화")

        # Request Handler
        self.request_handler = RequestHandler(
            llm_hosts=self.LLM_HOSTS,
            app_hosts=self.APP_HOSTS,
            llm_handler=self.llm_handler,
            app_handler=self.app_handler,
            server_client=self.server_client,
            cache_manager=self.cache_manager,
            log_manager=self.log_manager,
            public_ip=self.public_ip,
            private_ip=self.private_ip,
            hostname=self.hostname
        )
        print("[INIT] ✓ Request Handler 초기화")

        # Response Handler
        self.response_handler = ResponseHandler(
            llm_hosts=self.LLM_HOSTS,
            app_hosts=self.APP_HOSTS,
            cache_manager=self.cache_manager,
            notification_callback=None  # TODO: 알림 콜백 구현
        )
        print("[INIT] ✓ Response Handler 초기화")

        # ===== 초기화 완료 =====
        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 완료!")
        print(f"[INIT] LLM 호스트: {', '.join(sorted(self.LLM_HOSTS))}")
        print(f"[INIT] App/MCP 호스트: {', '.join(sorted(self.APP_HOSTS))}")
        print("="*60 + "\n")


    # ===== mitmproxy addon 인터페이스 =====

    def load(self, loader):
        """mitmproxy addon 로드 시 호출"""
        ctx.log.info("[Sentinel Proxy] addon loaded successfully")

    def request(self, flow: http.HTTPFlow):
        """
        Request 처리 - RequestHandler에 위임

        Args:
            flow: mitmproxy HTTPFlow 객체
        """
        self.request_handler.process(flow)

    def response(self, flow: http.HTTPFlow):
        """
        Response 처리 - ResponseHandler에 위임

        Args:
            flow: mitmproxy HTTPFlow 객체
        """
        self.response_handler.process(flow)

def create_addon(proxy_port: int = None) -> SentinelProxyAddon:
    """
    외부에서 import해서 mitmproxy addons에 주입할 때 사용.
    예)
      from sentinel_proxy.engines.sentinel_engine import create_addon
      addons = [create_addon(proxy_port=8081)]
    """
    return SentinelProxyAddon()
