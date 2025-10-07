#!/usr/bin/env python3
"""
통합 디스패처 - 호스트 기반 트래픽 라우팅 + 통합 로깅
LLM 트래픽과 App/MCP 트래픽을 적절한 핸들러로 전달하고,
추출된 데이터를 통합 로그 파일에 저장하며 서버로 전송합니다.
"""
import sys
import os
import json
import socket
import logging
from pathlib import Path
from datetime import datetime
from mitmproxy import http, ctx
from typing import Set, Dict, Any, Optional
import requests

# mitmproxy 로거 사용 (mitm_debug.log에 기록됨)
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력 (mitmproxy 로그 또는 print)"""
    if log:
        log.info(msg)
    else:
        print(msg)

# 핸들러 임포트
from llm_parser.llm_main import UnifiedLLMLogger
from app_parser.app_main import UnifiedAppLogger

# =========================================================
# 서버 전송 주소 (하드코딩)
SENTINEL_SERVER_URL = "https://158.180.72.194/logs"
REQUESTS_VERIFY_TLS = False
# =========================================================


def get_control_decision(log_entry: dict) -> dict:
    """
    서버로 제어 결정을 요청.
    - 반드시 POST /logs (JSON)
    - 프록시 환경변수 무시(trust_env=False)
    - (연결,읽기) 타임아웃 분리
    """
    try:
        info(f"서버에 요청 중... ({log_entry['host']}) -> {SENTINEL_SERVER_URL}")

        payload = log_entry

        session = requests.Session()
        session.trust_env = False
        session.proxies = {}

        timeout = (3.0, 12.0)

        response = session.post(
            SENTINEL_SERVER_URL,
            json=payload,
            timeout=timeout,
            verify=REQUESTS_VERIFY_TLS
        )

        if response.status_code == 200:
            decision = response.json()
            info(f"서버 응답: {decision}")
            return decision
        else:
            info(f"서버 오류: HTTP {response.status_code} {response.text[:200]}")
            return {'action': 'allow'}

    except requests.exceptions.ProxyError as e:
        info(f"[PROXY] 프록시 오류: {e}")
        return {'action': 'allow'}
    except requests.exceptions.SSLError as e:
        info(f"[TLS] 인증서 오류: {e}")
        return {'action': 'allow'}
    except requests.exceptions.ConnectTimeout:
        info("[NET] 연결 타임아웃")
        return {'action': 'allow'}
    except requests.exceptions.ReadTimeout:
        info("[NET] 읽기 타임아웃")
        return {'action': 'allow'}
    except requests.exceptions.RequestException as e:
        info(f"[NET] 요청 실패: {repr(e)}")
        return {'action': 'allow'}


class UnifiedDispatcher:
    """통합 디스패처 - 호스트에 따라 LLM 또는 App 핸들러로 라우팅 + 통합 로깅"""

    def __init__(self):
        # LLM 호스트 정의
        self.LLM_HOSTS: Set[str] = {
            "chatgpt.com", "claude.ai", "gemini.google.com",
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "api.openai.com", "api.anthropic.com"
        }

        # App/MCP 호스트 정의
        self.APP_HOSTS: Set[str] = {
            "api2.cursor.sh", "api3.cursor.sh", "repo42.cursor.sh",
            "metrics.cursor.sh", "localhost", "127.0.0.1"
        }

        # 초기화 시작 로그
        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 시작...")
        print("="*60)

        # 통합 로깅 설정
        self.base_dir = Path.home() / ".llm_proxy"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.unified_log_file = self.base_dir / "unified_requests.json"
        print(f"[INIT] 로그 디렉터리: {self.base_dir}")

        # 시스템 정보 캐싱
        self.hostname = socket.gethostname()
        print(f"[INIT] 호스트명: {self.hostname}")
        self.public_ip = self._get_public_ip()
        self.private_ip = self._get_private_ip()

        # 핸들러 초기화 (에러 처리 강화)
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

        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 완료!")
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
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]



    def _is_llm_request(self, host: str) -> bool:
        """LLM 요청인지 확인"""
        return any(llm_host in host for llm_host in self.LLM_HOSTS)

    def _is_app_request(self, host: str) -> bool:
        """App/MCP 요청인지 확인"""
        return any(app_host in host for app_host in self.APP_HOSTS)

    def save_unified_log(self, log_entry: Dict[str, Any]):
        """통합 로그 파일에 저장 (.llm_proxy/unified_requests.json)"""
        try:
            logs = []
            if self.unified_log_file.exists():
                try:
                    content = self.unified_log_file.read_text(encoding="utf-8").strip()
                    if content:
                        logs = json.loads(content)
                except (json.JSONDecodeError, OSError):
                    logs = []
            logs.append(log_entry)
            if len(logs) > 100:
                logs = logs[-100:]
            self.unified_log_file.write_text(
                json.dumps(logs, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            info(f"[ERROR] 통합 로그 저장 실패: {e}")

    def request(self, flow: http.HTTPFlow):
        """요청을 적절한 핸들러로 라우팅하고 통합 로깅 처리"""
        try:
            host = flow.request.pretty_host
            extracted_data = None
            interface = None

            # 모든 요청 호스트 로깅 (디버그용)
            info(f"[DISPATCHER] 요청 감지: {host} | {flow.request.method} {flow.request.path[:100]}")

            # LLM 트래픽 라우팅 (프롬프트 추출만)
            if self._is_llm_request(host):
                info(f"[DISPATCHER] LLM 요청으로 라우팅: {host}")
                if not hasattr(self, 'llm_handler') or self.llm_handler is None:
                    info(f"[DISPATCHER] ✗ LLM 핸들러가 초기화되지 않음!")
                    return
                extracted_data = self.llm_handler.extract_prompt_only(flow)
                interface = "llm"

            # App/MCP 트래픽 라우팅 (프롬프트 추출만)
            elif self._is_app_request(host):
                info(f"[DISPATCHER] App/MCP 요청으로 라우팅: {host}")
                if not hasattr(self, 'app_handler') or self.app_handler is None:
                    info(f"[DISPATCHER] ✗ App/MCP 핸들러가 초기화되지 않음!")
                    return
                extracted_data = self.app_handler.extract_prompt_only(flow)
                if extracted_data:
                    interface = extracted_data.get("interface", "app")
                else:
                    return  # 프롬프트 추출 실패

            # 매칭되지 않는 트래픽은 통과
            else:
                info(f"[DISPATCHER] 매칭되지 않는 호스트, 통과: {host}")
                return

            # 추출된 데이터가 없으면 종료
            if not extracted_data or not extracted_data.get("prompt"):
                return

            prompt = extracted_data["prompt"]
            info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt}")

            # 통합 로그 항목 생성
            log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": host,
                "hostname": self.hostname,
                "prompt": prompt,
                "attachment": {
                    "format": None,
                    "data": None
                },
                "interface": interface
            }

            # 서버로 전송 (홀딩)
            info("서버로 전송, 홀딩 시작...")
            start_time = datetime.now()

            decision = get_control_decision(log_entry)

            end_time = datetime.now()
            elapsed = (end_time - start_time).total_seconds()
            info(f"홀딩 완료! 소요시간: {elapsed:.1f}초")

            # 변조된 프롬프트 처리 (LLM만 지원)
            modified_prompt = decision.get('modified_prompt')
            if modified_prompt and interface == "llm":
                info(f"[MODIFY] {prompt[:30]}... -> {modified_prompt[:50]}...")
                # LLM 핸들러에게 패킷 변조 요청
                self.llm_handler.modify_request(flow, modified_prompt)

            # 통합 로그 저장 (holding_time 추가)
            log_entry["holding_time"] = elapsed
            self.save_unified_log(log_entry)

            info(f"{interface.upper()} 요청 처리 완료")

        except Exception as e:
            info(f"[ERROR] 디스패처 오류: {e}")
            import traceback
            traceback.print_exc()


# mitmproxy addon 등록
addons = [UnifiedDispatcher()]
