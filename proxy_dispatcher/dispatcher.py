#!/usr/bin/env python3
"""
통합 디스패처 (Orchestrator) - 호스트 기반 트래픽 라우팅
- mitmproxy 의존성을 제거하고 독립 실행형 서버 구조로 전환
"""
import os
import sys
import socket
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Set, Optional, Any
import logging
import threading # [추가] 클라이언트 연결 동시 처리를 위한 스레딩 모듈
import re # HTTP 요청 라인 파싱을 위해 추가
import select # HTTPS 터널링을 위한 select 모듈

# [수정] mitmproxy 모듈 제거
import requests

# 핸들러 임포트
# 이 모듈들은 외부에서 정의되어 있다고 가정합니다.
from llm_parser.llm_main import UnifiedLLMLogger
from app_parser.app_main import UnifiedAppLogger

# 분리된 모듈 임포트
from proxy_dispatcher.server_client import ServerClient
from proxy_dispatcher.cache_manager import FileCacheManager
from proxy_dispatcher.log_manager import LogManager
from proxy_dispatcher.request_handler import RequestHandler
from proxy_dispatcher.response_handler import ResponseHandler

# 공통 네트워크 유틸리티 (IP 조회)
from utils.network_utils import get_public_ip, get_private_ip


# [수정] 로깅은 Python 표준 라이브러리를 사용하도록 변경
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def info(msg):
    """로그 출력 (디버그 로그 파일에 기록)"""
    logger.info(msg)


# =========================================================
# Custom Flow 객체 (http.HTTPFlow 대체)
# =========================================================

# 실제 프록시 서버 구현 시 flow.request, flow.response를 담을 클래스 필요
class CustomFlow:
    """임시 HTTP/HTTPS 흐름 객체 (mitmproxy.http.HTTPFlow 대체)"""
    def __init__(self, request: Any = None, response: Any = None):
        self.request = request
        self.response = response

# =========================================================
# 설정 (하드코딩 → TODO: 설정 파일로 분리)
# =========================================================
SENTINEL_SERVER_URL = "https://bobsentinel.site/api/logs"
REQUESTS_VERIFY_TLS = False
CACHE_TIMEOUT_SECONDS = 10


# =========================================================
# 프록시 클라이언트 연결 처리 스레드
# =========================================================

class ProxyClientThread(threading.Thread):
    """
    각 클라이언트 연결을 처리하는 스레드
    현재는 HTTP 요청을 받아 연결을 종료하는 최소 기능만 구현
    """
    def __init__(self, client_socket, client_address, dispatcher: 'UnifiedDispatcher'):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address
        self.dispatcher = dispatcher
        self.daemon = True

    def run(self):
        try:
            # 클라이언트로부터 첫 번째 요청 라인을 읽습니다.
            self.client_socket.settimeout(5)
            # 클라이언트 소켓에서 데이터를 읽습니다 (최대 8192 바이트)
            request_data = self.client_socket.recv(8192)

            if not request_data:
                return

            # 요청 라인 파싱 (예: GET http://example.com/ HTTP/1.1)
            first_line = request_data.split(b'\n')[0].decode('utf-8', errors='ignore').strip()
            match = re.match(r"(\w+)\s+(.+)\s+HTTP/(\d\.\d)", first_line)

            if match:
                method, url, version = match.groups()
                info(f"[REQUEST] {self.client_address[0]}:{self.client_address[1]} - {method} {url}")

                if method == 'CONNECT':
                    # TODO: 1. HTTPS 요청 처리 (SSL/TLS 복호화) 로직 구현 필요
                    self._handle_https_connect(url, request_data)
                else:
                    # 2. HTTP 요청 처리 및 포워딩
                    self._handle_http_request(method, url, request_data)

            else:
                # 유효하지 않은 요청 형식
                self._send_response(b'HTTP/1.1 400 Bad Request\r\n\r\n', 400)

        except socket.timeout:
            # info(f"클라이언트 연결 타임아웃: {self.client_address}")
            pass
        except Exception as e:
            # info(f"클라이언트 처리 중 오류 발생: {e}")
            pass
        finally:
            # 연결 처리 후 소켓 닫기
            self.client_socket.close()

    def _send_response(self, header_bytes: bytes, status_code: int):
        """간단한 응답을 클라이언트에게 보냅니다."""
        try:
            self.client_socket.sendall(header_bytes)
            info(f"[RESPONSE] {self.client_address[0]}:{self.client_address[1]} - {status_code} Sent")
        except:
            pass
            
    def _handle_http_request(self, method: str, url: str, request_data: bytes):
        """HTTP 요청을 목적지 서버로 포워딩"""
        try:
            # URL에서 호스트와 경로 추출
            # 형식: http://host:port/path 또는 http://host/path
            if url.startswith('http://'):
                url = url[7:]  # 'http://' 제거
            elif url.startswith('https://'):
                url = url[8:]  # 'https://' 제거 (혹시 있을 경우)

            # 호스트:포트와 경로 분리
            if '/' in url:
                host_port, path = url.split('/', 1)
                path = '/' + path
            else:
                host_port = url
                path = '/'

            # 호스트와 포트 분리
            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                port = int(port)
            else:
                host = host_port
                port = 80

            info(f"[HTTP] 포워딩: {host}:{port}{path}")

            # 목적지 서버에 연결
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((host, port))

            # 원본 요청을 목적지로 전송
            target_socket.sendall(request_data)

            # 목적지 서버로부터 응답 수신
            response_data = b''
            while True:
                chunk = target_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk

                # Content-Length 헤더가 있으면 해당 크기만큼만 읽기
                if b'\r\n\r\n' in response_data and b'Content-Length:' in response_data:
                    headers_end = response_data.find(b'\r\n\r\n')
                    headers = response_data[:headers_end]

                    # Content-Length 추출
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-length:'):
                            content_length = int(line.split(b':')[1].strip())
                            body_start = headers_end + 4
                            body = response_data[body_start:]

                            # 필요한 만큼 더 읽기
                            while len(body) < content_length:
                                chunk = target_socket.recv(4096)
                                if not chunk:
                                    break
                                body += chunk
                                response_data += chunk
                            break

            target_socket.close()

            # 클라이언트에게 응답 전송
            self.client_socket.sendall(response_data)
            info(f"[HTTP] 응답 전송 완료: {len(response_data)} bytes")

        except Exception as e:
            info(f"[HTTP] 포워딩 실패: {e}")
            self._send_response(b'HTTP/1.1 502 Bad Gateway\r\n\r\n', 502)

    def _handle_https_connect(self, url: str, request_data: bytes):
        """HTTPS CONNECT 요청 - 투명 터널링 (복호화 없음)"""
        try:
            # 호스트:포트 추출
            if ':' in url:
                host, port = url.rsplit(':', 1)
                port = int(port)
            else:
                host = url
                port = 443

            info(f"[HTTPS] 터널링: {host}:{port}")

            # 목적지 서버에 연결
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((host, port))

            # 클라이언트에게 터널 성공 응답
            response = b'HTTP/1.1 200 Connection established\r\n\r\n'
            self.client_socket.sendall(response)

            # 양방향 터널링 (select 사용)
            self.client_socket.setblocking(False)
            target_socket.setblocking(False)

            sockets = [self.client_socket, target_socket]
            timeout = 60  # 타임아웃 60초

            while True:
                # 읽기 가능한 소켓 확인
                try:
                    readable, _, exceptional = select.select(sockets, [], sockets, timeout)
                except (OSError, ValueError):
                    break

                if not readable:
                    # 타임아웃
                    break

                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            # 연결 종료
                            target_socket.close()
                            info(f"[HTTPS] 터널 종료: {host}:{port}")
                            return

                        # 반대쪽 소켓으로 데이터 전송
                        if sock is self.client_socket:
                            target_socket.sendall(data)
                        else:
                            self.client_socket.sendall(data)

                    except (ConnectionResetError, BrokenPipeError):
                        target_socket.close()
                        info(f"[HTTPS] 터널 연결 끊김: {host}:{port}")
                        return

                for sock in exceptional:
                    target_socket.close()
                    info(f"[HTTPS] 터널 예외 발생: {host}:{port}")
                    return

            target_socket.close()
            info(f"[HTTPS] 터널 타임아웃: {host}:{port}")

        except Exception as e:
            info(f"[HTTPS] 터널링 실패: {e}")
            try:
                self._send_response(b'HTTP/1.1 502 Bad Gateway\r\n\r\n', 502)
            except:
                pass


class UnifiedDispatcher:
    """통합 디스패처 - Orchestrator"""
    # ... (UnifiedDispatcher.__init__ 및 기타 메소드 생략 - 변경 없음) ...
    def __init__(self, base_dir: Path, port: int, ca_cert: Path, ca_key: Path, allowed_hosts: Set[str]):
        """디스패처 초기화"""
        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 시작...")
        print("="*60)

        # [수정] main.py로부터 받은 인자 저장
        self.port = port
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.allowed_hosts = allowed_hosts
        
        # [수정] 설정 디렉토리 일관성 확보
        self.base_dir = base_dir 
        self.base_dir.mkdir(parents=True, exist_ok=True)
        print(f"[INIT] 설정 디렉터리: {self.base_dir}")


        # ===== 호스트 정의 =====
        # allowed_hosts 인자를 사용하여 LLM/APP 호스트 설정
        self.LLM_HOSTS: Set[str] = {h for h in allowed_hosts if 'api.' in h or 'chat' in h or 'gemini' in h or 'claude' in h}
        self.APP_HOSTS: Set[str] = allowed_hosts - self.LLM_HOSTS
        
        # [수정] 시스템 정보 캐싱 (IP 조회에 예외 처리 추가)
        self.hostname = socket.gethostname()
        print(f"[INIT] 호스트명: {self.hostname}")
        
        self.public_ip = "N/A (Failed)"
        try:
            self.public_ip = get_public_ip()
            print(f"[INIT] 공인 IP: {self.public_ip}")
        except Exception as e:
            # 외부 API 호출 실패 시 초기화 중단 없이 경고만 남기고 계속 진행
            print(f"[WARNING] 공인 IP 조회 실패 (네트워크 오류): {e}")

        self.private_ip = get_private_ip()
        print(f"[INIT] 사설 IP: {self.private_ip}")

        # ===== LLM/App 핸들러 초기화 =====
        print("\n[INIT] LLM 핸들러 초기화 중...")
        try:
            self.llm_handler = UnifiedLLMLogger()
            print("[INIT] ✓ LLM 핸들러 초기화 완료")
        except Exception as e:
            print(f"[INIT] ✗ LLM 핸들러 초기화 실패: {e}")
            raise

        print("\n[INIT] App/MCP 핸들러 초기화 중...")
        try:
            self.app_handler = UnifiedAppLogger()
            print("[INIT] ✓ App/MCP 핸들러 초기화 완료")
        except Exception as e:
            print(f"[INIT] ✗ App/MCP 핸들러 초기화 실패: {e}")
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

        # Response Handler (TODO: 구현 예정)
        self.response_handler = ResponseHandler(
            llm_hosts=self.LLM_HOSTS,
            app_hosts=self.APP_HOSTS,
            notification_callback=None
        )
        print("[INIT] ✓ Response Handler 초기화 (구현 예정)")

        # ===== 초기화 완료 =====
        print("\n" + "="*60)
        print("[INIT] 통합 디스패처 초기화 완료!")
        print(f"[INIT] LLM 호스트: {', '.join(sorted(self.LLM_HOSTS))}")
        print(f"[INIT] App/MCP 호스트: {', '.join(sorted(self.APP_HOSTS))}")
        print(f"[INIT] 프록시 포트: {self.port}")
        print(f"[INIT] CA 인증서: {self.ca_cert.name}")
        print("="*60 + "\n")
    
    def _on_file_timeout(self, file_id: str, cached_data: dict):
        # ... (기존 _on_file_timeout 로직 유지)
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


    # [수정] mitmproxy addon 인터페이스 대신 일반 메소드 유지 (CustomFlow 사용)
    def request(self, flow: CustomFlow):
        """
        Request 처리 - RequestHandler에 위임 (실제 프록시 서버에서 호출됨)
        """
        self.request_handler.process(flow)

    def response(self, flow: CustomFlow):
        """
        Response 처리 - ResponseHandler에 위임 (실제 프록시 서버에서 호출됨)
        """
        # TODO: Response 처리 활성화
        # self.response_handler.process(flow)
        pass


def run_proxy_server(dispatcher: UnifiedDispatcher):
    """
    프록시 서버의 메인 실행 루프 (HTTP 프록시 구현 시작)
    """
    info(f"[START] 프록시 서버 리스닝 시작 (Port: {dispatcher.port})...")
    
    server_socket = None
    try:
        # 소켓 생성 및 바인딩
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', dispatcher.port))
        server_socket.listen(5)
        info(f"[START] HTTP/HTTPS 리스너 127.0.0.1:{dispatcher.port} 에서 활성화되었습니다.")

        while True:
            # 클라이언트 연결 수락
            client_socket, client_address = server_socket.accept()
            # 각 연결을 스레드로 처리
            thread = ProxyClientThread(client_socket, client_address, dispatcher)
            thread.start()

    except KeyboardInterrupt:
        info("[STOP] 서버 프로세스 종료 요청 수신.")
    except Exception as e:
        info(f"[CRITICAL] 서버 실행 중 오류 발생: {e}")
    finally:
        if server_socket:
            server_socket.close()
        info("[STOP] 프록시 서버 리스닝 종료.")


if __name__ == "__main__":
    # 1. 인자 파싱
    parser = argparse.ArgumentParser(description="Sentinel Proxy Dispatcher")
    parser.add_argument("--port", type=int, required=True, help="프록시가 리스닝할 포트 번호")
    parser.add_argument("--ca-cert", type=Path, required=True, help="CA 인증서 파일 경로")
    parser.add_argument("--ca-key", type=Path, required=True, help="CA 개인 키 파일 경로")
    parser.add_argument("--allow-hosts", type=str, required=True, help="허용된 호스트 목록 (콤마 구분)")
    
    args = parser.parse_args()
    
    # 2. 로깅 설정 (sub-process용)
    
    # 3. 인자 준비
    allowed_hosts_set = set(args.allow_hosts.split(','))
    
    # [수정] base_dir 경로를 main.py와 일치하도록 하드코딩
    base_dir = Path.home() / ".sentinel_proxy"

    # 4. 디스패처 초기화
    try:
        # 이 시점에서 Sentinel CA 인증서 파일 경로와 키 경로가 dispatcher에 전달됩니다.
        dispatcher = UnifiedDispatcher(
            base_dir=base_dir,
            port=args.port,
            ca_cert=args.ca_cert,
            ca_key=args.ca_key,
            allowed_hosts=allowed_hosts_set
        )
        
        # 5. 서버 실행 루프 진입
        run_proxy_server(dispatcher)

    except Exception as e:
        print("\n" + "="*50)
        print(f"CRITICAL: Dispatcher 초기화 또는 실행 중 치명적인 오류 발생: {e}")
        import traceback
        traceback.print_exc(file=sys.stdout) # 오류를 디버그 로그 파일(stdout)에 출력
        print("="*50 + "\n")
        sys.exit(1)