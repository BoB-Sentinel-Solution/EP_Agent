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
import threading
import time
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


def get_control_decision(log_entry: dict, step1_time: float) -> tuple:
    """
    서버로 제어 결정을 요청.
    - 반드시 POST /logs (JSON)
    - 프록시 환경변수 무시(trust_env=False)
    - (연결,읽기) 타임아웃 분리
    - 반환: (decision, step2_timestamp, step3_timestamp)
    """
    try:
        info(f"서버에 요청 중... ({log_entry['host']}) -> {SENTINEL_SERVER_URL}")

        payload = log_entry

        session = requests.Session()
        session.trust_env = False
        session.proxies = {}

        timeout = (3.0, 12.0)

        step2_timestamp = datetime.now()
        response = session.post(
            SENTINEL_SERVER_URL,
            json=payload,
            timeout=timeout,
            verify=REQUESTS_VERIFY_TLS
        )
        step3_timestamp = datetime.now()

        if response.status_code == 200:
            decision = response.json()
            info(f"서버 응답: {decision}")
            return (decision, step2_timestamp, step3_timestamp)
        else:
            info(f"서버 오류: HTTP {response.status_code} {response.text[:200]}")
            return ({'action': 'allow'}, step2_timestamp, step3_timestamp)

    except requests.exceptions.ProxyError as e:
        info(f"[PROXY] 프록시 오류: {e}")
        return ({'action': 'allow'}, None, None)
    except requests.exceptions.SSLError as e:
        info(f"[TLS] 인증서 오류: {e}")
        return ({'action': 'allow'}, None, None)
    except requests.exceptions.ConnectTimeout:
        info("[NET] 연결 타임아웃")
        return ({'action': 'allow'}, None, None)
    except requests.exceptions.ReadTimeout:
        info("[NET] 읽기 타임아웃")
        return ({'action': 'allow'}, None, None)
    except requests.exceptions.RequestException as e:
        info(f"[NET] 요청 실패: {repr(e)}")
        return ({'action': 'allow'}, None, None)




class UnifiedDispatcher:
    """통합 디스패처 - 호스트에 따라 LLM 또는 App 핸들러로 라우팅 + 통합 로깅"""

    def __init__(self):
        # LLM 호스트 정의
        self.LLM_HOSTS: Set[str] = {
            "chatgpt.com", "oaiusercontent.com",  # ChatGPT + 파일 업로드
            "claude.ai", "gemini.google.com",
            "chat.deepseek.com", "groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "api.openai.com", "api.anthropic.com"
        }

        # 파일 캐시: {file_id: {"attachment": {...}, "timestamp": datetime}}
        self.file_cache: Dict[str, Dict[str, Any]] = {}

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

        # 타임아웃 체크 스레드 시작
        self.cache_timeout_seconds = 10  # 10초 타임아웃
        self._thread_running = True
        self.timeout_thread = threading.Thread(target=self._check_timeout_files, daemon=True)
        self.timeout_thread.start()
        print("[INIT] 파일 타임아웃 체크 스레드 시작 (10초)\n")

    def _check_timeout_files(self):
        """주기적으로 캐시를 확인하여 타임아웃된 파일을 서버로 전송"""
        while self._thread_running:
            time.sleep(2)  # 2초마다 체크
            current_time = datetime.now()

            for file_id, cached_data in list(self.file_cache.items()):
                timestamp = cached_data["timestamp"]
                elapsed = (current_time - timestamp).total_seconds()

                if elapsed > self.cache_timeout_seconds:
                    info(f"[TIMEOUT] 파일 타임아웃: {file_id} ({elapsed:.1f}초 경과)")
                    info(f"[TIMEOUT] 이미지만 단독 전송 모드")

                    attachment = cached_data["attachment"]
                    parse_time = cached_data.get("parse_time", 0)

                    # 서버로 전송 (이미지만)
                    log_entry = {
                        "time": datetime.now().isoformat(),
                        "public_ip": self.public_ip,
                        "private_ip": self.private_ip,
                        "host": "oaiusercontent.com",
                        "PCName": self.hostname,
                        "prompt": f"[FILE_ONLY] {attachment.get('format')} upload",
                        "attachment": attachment,
                        "interface": "llm"
                    }

                    start_time = datetime.now()
                    decision, step2_timestamp, step3_timestamp = get_control_decision(log_entry, parse_time)
                    end_time = datetime.now()
                    elapsed_holding = (end_time - start_time).total_seconds()

                    info(f"[TIMEOUT] 파일 홀딩 완료: {elapsed_holding:.4f}초")

                    # 통합 로그 저장
                    log_entry["holding_time"] = elapsed_holding
                    self.save_unified_log(log_entry)

                    # 캐시에서 제거
                    del self.file_cache[file_id]
                    info(f"[TIMEOUT] 파일 처리 완료: {file_id}")

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

    def _extract_file_id(self, path: str) -> Optional[str]:
        """URL 경로에서 File ID 추출"""
        if '/files/' in path:
            try:
                return path.split('/files/')[1].split('/')[0]
            except (IndexError, AttributeError):
                return None
        return None

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
            method = flow.request.method
            path = flow.request.path
            extracted_data = None
            interface = None

            # 모든 요청 호스트 로깅 (디버그용)
            info(f"[DISPATCHER] 요청 감지: {host} | {method} {path[:100]}")

            # LLM 트래픽 라우팅 (프롬프트 추출만)
            if self._is_llm_request(host):
                info(f"[DISPATCHER] LLM 요청으로 라우팅: {host}")
                if not hasattr(self, 'llm_handler') or self.llm_handler is None:
                    info(f"[DISPATCHER] ✗ LLM 핸들러가 초기화되지 않음!")
                    return

                # PUT 요청 처리 (파일 업로드) - 캐시에만 저장
                if method == "PUT" and "oaiusercontent" in host:
                    file_id = self._extract_file_id(path)
                    step1_start = datetime.now()
                    extracted_data = self.llm_handler.extract_prompt_only(flow)
                    step1_end = datetime.now()
                    step1_time = (step1_end - step1_start).total_seconds()

                    if not file_id or not extracted_data or not extracted_data.get("attachment"):
                        info(f"[FILE] 파일 추출 실패 - file_id={file_id}")
                        return

                    attachment = extracted_data["attachment"]
                    if not attachment or not attachment.get("format"):
                        info(f"[FILE] attachment 형식 오류")
                        return

                    # 캐시에 파일 정보 저장 (타임아웃: 10초)
                    self.file_cache[file_id] = {
                        "attachment": attachment,
                        "timestamp": datetime.now(),
                        "parse_time": step1_time
                    }
                    info(f"[CACHE] 파일 저장: {file_id} | {attachment.get('format')} | {step1_time:.4f}초 | POST 대기중...")
                    return  # POST 요청을 기다림

                # POST 요청 처리 (프롬프트)
                step1_start = datetime.now()
                extracted_data = self.llm_handler.extract_prompt_only(flow)
                step1_end = datetime.now()
                info(f"[Step0] 프롬프트 파싱 끝난 시간: {step1_end.strftime('%H:%M:%S.%f')[:-3]}")
                step1_time = (step1_end - step1_start).total_seconds()
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
                interface = "llm"

            # App/MCP 트래픽 라우팅 (프롬프트 추출만)
            elif self._is_app_request(host):
                info(f"[DISPATCHER] App/MCP 요청으로 라우팅: {host}")
                if not hasattr(self, 'app_handler') or self.app_handler is None:
                    info(f"[DISPATCHER] ✗ App/MCP 핸들러가 초기화되지 않음!")
                    return
                step1_start = datetime.now()
                extracted_data = self.app_handler.extract_prompt_only(flow)
                step1_end = datetime.now()
                step1_time = (step1_end - step1_start).total_seconds()
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
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
            attachment = extracted_data.get("attachment", {"format": None, "data": None})

            # 캐시에서 파일 정보 가져오기 (LLM 요청만 해당)
            if interface == "llm" and flow.request.content:
                try:
                    request_body = flow.request.content.decode('utf-8', errors='ignore')
                    for file_id, cached_data in list(self.file_cache.items()):
                        # File ID 정규화 (하이픈 제거하여 비교)
                        normalized_file_id = file_id.replace('-', '')
                        if normalized_file_id in request_body or file_id in request_body:
                            attachment = cached_data["attachment"]
                            info(f"[CACHE] 파일 매칭: {file_id} | {attachment.get('format')}")
                            del self.file_cache[file_id]
                            break
                except Exception as e:
                    info(f"[CACHE] 오류: {e}")

            # 파일 첨부 정보 로깅
            if attachment and attachment.get("format"):
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt} [파일: {attachment.get('format')}]")
            else:
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt}")

            # 통합 로그 항목 생성
            log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": host,
                "PCName": self.hostname,
                "prompt": prompt,
                "attachment": attachment,
                "interface": interface
            }

            # 서버로 전송 (홀딩)
            info("서버로 전송, 홀딩 시작...")
            start_time = datetime.now()
            info(f"서버로 전송한 시간: {start_time.strftime('%H:%M:%S.%f')[:-3]}")

            prompt_to_server_time=(start_time-step1_end).total_seconds()
            info(f"프롬프트 파싱부터 서버로 전송까지 걸린 시간: {prompt_to_server_time:.4f}초")


            decision, step2_timestamp, step3_timestamp = get_control_decision(log_entry, step1_time)
            end_time = datetime.now()

            if step2_timestamp and step3_timestamp:
                info(f"[Step2] 서버 요청 시점: {step2_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                info(f"[Step3] 서버 응답 시점: {step3_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                network_time = (step3_timestamp - step2_timestamp).total_seconds()
                info(f"네트워크 송수신 시간: {network_time:.4f}초")

            elapsed = (end_time - start_time).total_seconds()
            info(f"홀딩 완료! 소요시간: {elapsed:.4f}초")

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
