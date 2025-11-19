#!/usr/bin/env python3
"""
Sentinel Proxy Server - 자체 HTTP/HTTPS 프록시 서버
선택적 TLS 인터셉트: LLM 호스트만 복호화, 나머지는 투명 터널링
"""
import asyncio
import argparse
import logging
import traceback
from pathlib import Path
from typing import Set

from sentinel_proxy.tunnel_handler import HTTPSTunnelHandler
from sentinel_proxy.tls_interceptor import TLSInterceptor
from sentinel_proxy.http_handler import HTTPHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# SSL 및 asyncio 경고 억제
logging.getLogger('asyncio').setLevel(logging.ERROR)


class SentinelProxyServer:
    """
    자체 HTTP/HTTPS 프록시 서버
    - asyncio 기반 TCP 서버
    - 선택적 HTTPS 인터셉트 (LLM 호스트)
    - 투명 터널링 (나머지 호스트)
    """

    def __init__(
        self,
        port: int,
        ca_cert_path: Path,
        ca_key_path: Path,
        addon_instance,
        cert_manager,
        llm_hosts: Set[str] = None
    ):
        self.port = port
        self.llm_hosts = llm_hosts or set()

        # 핸들러 초기화
        self.tunnel_handler = HTTPSTunnelHandler()
        self.tls_interceptor = TLSInterceptor(cert_manager)
        self.http_handler = HTTPHandler(addon_instance, port)

        print(f"[Sentinel Proxy] 초기화 완료")
        print(f"[Sentinel Proxy] 포트: {port}")
        print(f"[Sentinel Proxy] CA 인증서: {ca_cert_path}")
        print(f"[Sentinel Proxy] TLS 인터셉트 대상: {len(self.llm_hosts)}개 호스트")

    async def start(self):
        """프록시 서버 시작"""
        print(f"[Sentinel Proxy] Addon 초기화 완료")

        server = await asyncio.start_server(
            self.handle_client,
            '127.0.0.1',
            self.port
        )

        addr = server.sockets[0].getsockname()
        print(f"[Sentinel Proxy] 서버 시작: {addr[0]}:{addr[1]}")
        print(f"[Sentinel Proxy] Ctrl+C로 종료")

        try:
            async with server:
                await server.serve_forever()
        except KeyboardInterrupt:
            print(f"[Sentinel Proxy] 키보드 인터럽트 감지")
        except Exception as e:
            print(f"[Sentinel Proxy] 서버 오류: {e}")
        finally:
            # 서버 정리
            server.close()
            await server.wait_closed()
            print(f"[Sentinel Proxy] 서버 정리 완료")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        클라이언트 연결 처리
        - HTTP CONNECT 요청 → 호스트 확인 후 라우팅
        - 일반 HTTP 요청 → 직접 프록싱
        """
        client_info = None
        try:
            # 클라이언트 정보 가져오기
            try:
                client_info = writer.get_extra_info('peername')
                logger.debug(f"[Proxy] 새 클라이언트 연결: {client_info}")
            except:
                client_info = "unknown"

            # 첫 줄 읽기 (요청 라인)
            try:
                request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                logger.debug(f"[Proxy] 클라이언트 요청 타임아웃: {client_info}")
                return

            if not request_line:
                logger.debug(f"[Proxy] 빈 요청으로 연결 종료: {client_info}")
                return

            request_line = request_line.decode('utf-8', errors='ignore')
            logger.debug(f"[Proxy] 요청 라인: {request_line.strip()}")

            # CONNECT 메서드 확인 (HTTPS)
            if request_line.startswith('CONNECT'):
                await self.handle_connect(request_line, reader, writer)
            else:
                # 일반 HTTP 요청 처리
                await self.handle_http(request_line, reader, writer)

        except asyncio.CancelledError:
            # 태스크 취소는 정상적인 종료 상황
            logger.debug(f"[Proxy] 클라이언트 연결 취소됨: {client_info}")
            raise  # CancelledError는 반드시 재발생
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # 네트워크 연결 오류 - 정상적인 상황
            logger.debug(f"[Proxy] 연결 오류 (정상): {client_info} - {e}")
        except Exception as e:
            logger.error(f"[Proxy] 클라이언트 처리 오류: {client_info} - {e}")
            import traceback
            traceback.print_exc()
        finally:
            # 연결 정리 (안전한 방식)
            await self._safe_close_writer(writer, client_info)

    async def _safe_close_writer(self, writer: asyncio.StreamWriter, client_info):
        """Writer 안전 정리"""
        try:
            if not writer.is_closing():
                writer.close()
                try:
                    # 짧은 타임아웃으로 wait_closed() 호출
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                    logger.debug(f"[Proxy] Writer 정리 완료: {client_info}")
                except asyncio.TimeoutError:
                    logger.debug(f"[Proxy] Writer 정리 타임아웃: {client_info}")
                except Exception as e:
                    logger.debug(f"[Proxy] Writer wait_closed 오류: {client_info} - {e}")
        except Exception as e:
            logger.debug(f"[Proxy] Writer 정리 중 오류: {client_info} - {e}")

    async def handle_http(self, request_line: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        일반 HTTP 요청 처리
        - GET, POST, PUT 등 일반 HTTP 메소드
        - 호스트 확인 후 보안 엔진 처리 또는 직접 프록싱
        """
        try:
            # HTTP 요청 파싱 (GET http://example.com/path HTTP/1.1)
            parts = request_line.strip().split()
            if len(parts) < 3:
                logger.error(f"[HTTP] 잘못된 HTTP 요청 형식: {request_line.strip()}")
                return

            method, url, http_version = parts[0], parts[1], parts[2]

            # URL에서 호스트 추출
            if url.startswith('http://'):
                # 절대 URL: http://example.com/path
                url_without_scheme = url[7:]  # http:// 제거
                if '/' in url_without_scheme:
                    host_port, path = url_without_scheme.split('/', 1)
                    path = '/' + path
                else:
                    host_port = url_without_scheme
                    path = '/'
            elif url.startswith('/'):
                # 상대 URL: 호스트 헤더에서 추출 필요
                host_port = None
                path = url
            else:
                logger.error(f"[HTTP] 지원하지 않는 URL 형식: {url}")
                return

            # 호스트:포트 분리
            if host_port and ':' in host_port:
                host, port_str = host_port.rsplit(':', 1)
                port = int(port_str)
            elif host_port:
                host = host_port
                port = 80  # HTTP 기본 포트
            else:
                # Host 헤더에서 추출
                host, port = await self._extract_host_from_headers(reader)
                if not host:
                    logger.error(f"[HTTP] 호스트를 찾을 수 없습니다")
                    return

            logger.debug(f"[HTTP] {method} {host}:{port}{path}")

            # 나머지 헤더 읽기 (첫 번째 요청 라인 이미 읽음)
            headers_data = request_line.encode('utf-8')

            # 추가 헤더들 읽기
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n' or line == b'\n':
                    headers_data += line
                    break
                headers_data += line

            # Content-Length가 있으면 body도 읽기
            body = b''
            headers_text = headers_data.decode('utf-8', errors='ignore')
            for line in headers_text.split('\n'):
                if line.lower().startswith('content-length:'):
                    try:
                        content_length = int(line.split(':', 1)[1].strip())
                        if content_length > 0:
                            body = await reader.read(content_length)
                        break
                    except:
                        pass

            # 전체 HTTP 요청 데이터
            full_request = headers_data + body

            # 호스트 확인 후 라우팅
            if self._should_intercept(host):
                # LLM/App 호스트: 보안 엔진 처리
                logger.debug(f"[ROUTE] HTTP 보안 처리 → {host}")
                await self._handle_http_with_security(full_request, reader, writer, host, port, method, path, http_version)
            else:
                # 일반 호스트: 직접 프록싱
                logger.debug(f"[ROUTE] HTTP 직접 프록싱 → {host}")
                await self._handle_http_proxy(full_request, reader, writer, host, port)

        except asyncio.CancelledError:
            logger.debug(f"[HTTP] HTTP 처리 취소됨: {host if 'host' in locals() else 'unknown'}")
            raise  # CancelledError는 반드시 재발생
        except Exception as e:
            logger.error(f"[HTTP] HTTP 처리 오류: {e}")
            import traceback
            traceback.print_exc()

    async def _extract_host_from_headers(self, reader: asyncio.StreamReader) -> tuple:
        """Host 헤더에서 호스트 정보 추출"""
        try:
            # 현재 위치 저장 (헤더를 다시 읽어야 하므로)
            headers = []
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n' or line == b'\n':
                    break
                headers.append(line)

                # Host 헤더 찾기
                line_str = line.decode('utf-8', errors='ignore').strip()
                if line_str.lower().startswith('host:'):
                    host_value = line_str.split(':', 1)[1].strip()
                    if ':' in host_value:
                        host, port_str = host_value.rsplit(':', 1)
                        return host, int(port_str)
                    else:
                        return host_value, 80

            return None, 80
        except Exception:
            return None, 80

    async def _handle_http_with_security(self, full_request: bytes, client_reader: asyncio.StreamReader,
                                       client_writer: asyncio.StreamWriter, host: str, port: int,
                                       method: str, path: str, http_version: str):
        """보안 엔진을 통한 HTTP 처리"""
        try:
            # 서버 연결
            server_reader, server_writer = await asyncio.open_connection(host, port)

            try:
                # 첫 번째 요청 전송
                server_writer.write(full_request)
                await server_writer.drain()

                # HTTP 교환 처리 (보안 엔진 연동)
                await self.http_handler.handle_http_exchange(
                    client_reader, client_writer,
                    server_reader, server_writer,
                    host, port,
                    first_request_sent=True
                )
            finally:
                # 서버 연결 정리
                try:
                    if not server_writer.is_closing():
                        server_writer.close()
                        await server_writer.wait_closed()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"[HTTP] 보안 처리 오류: {e}")
            # 에러 응답 전송
            error_response = f"{http_version} 502 Bad Gateway\r\nConnection: close\r\n\r\nProxy Error: {e}".encode()
            client_writer.write(error_response)
            await client_writer.drain()

    async def _handle_http_proxy(self, full_request: bytes, client_reader: asyncio.StreamReader,
                                client_writer: asyncio.StreamWriter, host: str, port: int):
        """직접 HTTP 프록싱 (보안 처리 없음)"""
        try:
            # 서버 연결
            server_reader, server_writer = await asyncio.open_connection(host, port)

            try:
                # 요청 전송
                server_writer.write(full_request)
                await server_writer.drain()

                # 양방향 데이터 전달
                await asyncio.gather(
                    self._pipe_data(client_reader, server_writer, f"[HTTP-C→S] {host}"),
                    self._pipe_data(server_reader, client_writer, f"[HTTP-S→C] {host}")
                )
            finally:
                # 서버 연결 정리
                try:
                    if not server_writer.is_closing():
                        server_writer.close()
                        await server_writer.wait_closed()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"[HTTP] 직접 프록싱 오류: {e}")
            # 에러 응답 전송
            error_response = f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nProxy Error: {e}".encode()
            client_writer.write(error_response)
            await client_writer.drain()

    async def _pipe_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, log_prefix: str):
        """데이터 파이프라인 (양방향 전달)"""
        try:
            while True:
                try:
                    data = await reader.read(8192)
                    if not data:
                        logger.debug(f"{log_prefix} 연결 종료 (EOF)")
                        break
                    writer.write(data)
                    await writer.drain()
                except asyncio.CancelledError:
                    logger.debug(f"{log_prefix} 파이프 취소됨")
                    raise  # CancelledError는 반드시 재발생
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.debug(f"{log_prefix} 연결 오류: {e}")
                    break
        except Exception as e:
            logger.debug(f"{log_prefix} 파이프 오류: {e}")

    async def handle_connect(self, request_line: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        HTTPS CONNECT 처리
        - LLM 호스트: TLS 인터셉트
        - 나머지: 투명 터널링
        """
        try:
            # "CONNECT host:port HTTP/1.1" 파싱
            parts = request_line.split()
            if len(parts) < 2:
                # writer는 handle_client에서 정리됨
                return

            host_port = parts[1]
            if ':' in host_port:
                host, port_str = host_port.rsplit(':', 1)
                port = int(port_str)
            else:
                host = host_port
                port = 443

            logger.debug(f"[CONNECT] {host}:{port}")

            # 나머지 헤더 읽기 (빈 줄까지)
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n' or line == b'\n':
                    break

            # 클라이언트에게 연결 성공 응답
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # 호스트 확인 후 라우팅
            if self._should_intercept(host):
                # LLM/App 호스트: TLS 인터셉트 (복호화 및 보안 검사)
                logger.debug(f"[ROUTE] TLS 인터셉트 → {host}")
                await self.tls_interceptor.intercept(reader, writer, host, port, self.http_handler)
            else:
                # 일반 호스트: 투명 터널링 (암호화 상태 유지)
                logger.debug(f"[ROUTE] 투명 터널링 → {host}")
                await self.tunnel_handler.handle(reader, writer, host, port)

        except asyncio.CancelledError:
            # 태스크 취소는 정상적인 종료 상황
            logger.debug(f"[CONNECT] 연결 취소됨: {host if 'host' in locals() else 'unknown'}")
            raise  # CancelledError는 반드시 재발생
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # 네트워크 연결 오류 - 정상적인 상황
            logger.debug(f"[CONNECT] 연결 오류 (정상): {host if 'host' in locals() else 'unknown'} - {e}")
        except Exception as e:
            logger.error(f"[CONNECT] 처리 오류: {e}")
            import traceback
            traceback.print_exc()

    def _should_intercept(self, host: str) -> bool:
        """
        호스트가 인터셉트 대상인지 확인

        Args:
            host: 대상 호스트

        Returns:
            True if 인터셉트 대상, False otherwise
        """
        # Sentinel 서버는 절대 인터셉트 안 함 (투명 터널링)
        if 'bobsentinel.site' in host:
            return False

        # Claude.ai 웹은 Cloudflare 때문에 투명 터널링 (API만 인터셉트)
        if host == 'claude.ai' or host.endswith('.claude.ai'):
            # api.anthropic.com만 인터셉트
            return False

        # 정확히 일치하거나 서브도메인 일치
        if host in self.llm_hosts:
            return True

        # 서브도메인 체크 (예: api.openai.com → openai.com)
        for llm_host in self.llm_hosts:
            if host.endswith('.' + llm_host):
                return True

        return False


# ===== 실행 진입점 =====
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Sentinel Proxy Server')
    parser.add_argument('--port', type=int, required=True, help='프록시 포트')
    parser.add_argument('--ca-cert', required=True, help='CA 인증서 경로')
    parser.add_argument('--ca-key', required=True, help='CA 키 경로')
    parser.add_argument('--llm-hosts', nargs='*', default=[], help='인터셉트 대상 호스트 목록')
    args = parser.parse_args()

    # CertificateManager 생성 (서버 인증서 동적 생성용)
    from proxy.certificate_manager import CertificateManager
    mitm_dir = Path(args.ca_cert).parent
    cert_manager = CertificateManager(mitm_dir)

    # addon 생성 (프록시 포트 전달)
    from sentinel_proxy.engines.sentinel_engine import create_addon
    addon = create_addon(proxy_port=args.port)

    # LLM 호스트 목록
    llm_hosts = set(args.llm_hosts) if args.llm_hosts else set()

    # 프록시 서버 생성
    server = SentinelProxyServer(
        port=args.port,
        ca_cert_path=Path(args.ca_cert),
        ca_key_path=Path(args.ca_key),
        addon_instance=addon,
        cert_manager=cert_manager,
        llm_hosts=llm_hosts
    )

    # 서버 시작
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[Sentinel Proxy] 종료 중...")
        # 캐시된 임시 파일 정리
        server.tls_interceptor.cleanup()
        print("[Sentinel Proxy] 정리 완료")
