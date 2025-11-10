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

import requests

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
CACHE_TIMEOUT_SECONDS = 10


class SentinelProxyAddon:
    """
    Sentinel Proxy mitmproxy Addon
    - 기존 UnifiedDispatcher의 모든 기능 유지
    - mitmproxy addon 인터페이스 제공
    """

    def __init__(self, proxy_port: int = None):
        """디스패처 초기화"""
        print("\n" + "="*60)
        print("[INIT] Sentinel Proxy Addon 초기화 시작...")
        print("="*60)

        self.proxy_port = proxy_port
        if proxy_port:
            print(f"[INIT] 프록시 포트: {proxy_port}")

        # ===== 호스트 정의 =====
        self.LLM_HOSTS: Set[str] = {
            "chatgpt.com", "oaiusercontent.com",  # ChatGPT + 파일 업로드
            "claude.ai",  # 프록시 헤더 제거로 Cloudflare 우회
            "gemini.google.com",
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "api.openai.com", "api.anthropic.com"
        }

        self.APP_HOSTS: Set[str] = {
            # Cursor 관련
            "api2.cursor.sh", "api3.cursor.sh", "repo42.cursor.sh",
            "metrics.cursor.sh", "localhost", "127.0.0.1",

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
        self.public_ip = self._get_public_ip()
        self.private_ip = self._get_private_ip()

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
            verify_tls=REQUESTS_VERIFY_TLS,
            proxy_port=self.proxy_port
        )
        print(f"[INIT] ✓ 서버 클라이언트 초기화: {SENTINEL_SERVER_URL}")

        # 로그 매니저
        self.log_manager = LogManager(
            log_file_path=self.base_dir / "unified_requests.json",
            max_entries=100
        )
        print("[INIT] ✓ 로그 매니저 초기화")

        # 파일 캐시 매니저 (타임아웃 콜백 등록)
        self.cache_manager = FileCacheManager(
            timeout_seconds=CACHE_TIMEOUT_SECONDS,
            on_timeout=self._on_file_timeout
        )
        print(f"[INIT] ✓ 파일 캐시 매니저 초기화 ({CACHE_TIMEOUT_SECONDS}초 타임아웃)")

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
            notification_callback=None
        )
        print("[INIT] ✓ Response Handler 초기화")

        # ===== 초기화 완료 =====
        print("\n" + "="*60)
        print("[INIT] Sentinel Proxy Addon 초기화 완료!")
        print(f"[INIT] LLM 호스트: {', '.join(sorted(self.LLM_HOSTS))}")
        print(f"[INIT] App/MCP 호스트: {', '.join(sorted(self.APP_HOSTS))}")
        print("="*60 + "\n")

    def _get_public_ip(self) -> str:
        """공인 IP 조회 (초기화 시 1회)"""
        try:
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            response = session.get('https://api.ipify.org?format=json', timeout=3, verify=False)
            if response.status_code == 200:
                public_ip = response.json().get('ip', 'unknown')
                print(f"[INFO] 공인 IP 조회 성공: {public_ip}")
                return public_ip
            return 'unknown'
        except Exception as e:
            print(f"[WARN] 공인 IP 조회 실패: {e}")
            return 'unknown'

    def _get_private_ip(self) -> str:
        """사설 IP 조회"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return 'unknown'

    def _on_file_timeout(self, file_id: str, cached_data: dict):
        """
        파일 타임아웃 콜백 - 이미지만 단독 전송

        Args:
            file_id: 파일 식별자
            cached_data: 캐시된 파일 데이터
        """
        info(f"[TIMEOUT] 이미지만 단독 전송 모드")

        attachment = cached_data["attachment"]
        parse_time = cached_data.get("parse_time", 0)

        # 호스트 정보 추출
        if file_id.startswith("claude:"):
            file_host = "claude.ai"
        elif file_id.startswith("file-") or "/" in file_id:  # ChatGPT 형식
            file_host = "chatgpt.com"
        else:
            file_host = "unknown"

        # 로그 엔트리 생성
        log_entry = {
            "time": datetime.now().isoformat(),
            "public_ip": self.public_ip,
            "private_ip": self.private_ip,
            "host": file_host,
            "PCName": self.hostname,
            "prompt": f"[FILE_ONLY]",
            "attachment": attachment,
            "interface": "llm"
        }

        # 서버로 전송
        start_time = datetime.now()
        decision, step2_timestamp, step3_timestamp = self.server_client.get_control_decision(log_entry, parse_time)
        end_time = datetime.now()
        elapsed_holding = (end_time - start_time).total_seconds()

        info(f"[TIMEOUT] 파일 홀딩 완료: {elapsed_holding:.4f}초")

        # 통합 로그 저장
        log_entry["holding_time"] = elapsed_holding
        self.log_manager.save_log(log_entry)
        info(f"[TIMEOUT] 파일 처리 완료: {file_id}")

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
    return SentinelProxyAddon(proxy_port=proxy_port)
