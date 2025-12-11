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

        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        클라이언트 연결 처리
        - HTTP CONNECT 요청 → 호스트 확인 후 라우팅
        - 일반 HTTP 요청 → 직접 프록싱 (TODO)
        """
        try:
            # 첫 줄 읽기 (요청 라인)
            request_line = await reader.readline()
            if not request_line:
                # 빈 요청 - writer는 finally에서 정리됨
                return

            request_line = request_line.decode('utf-8', errors='ignore')

            # CONNECT 메서드 확인 (HTTPS)
            if request_line.startswith('CONNECT'):
                await self.handle_connect(request_line, reader, writer)
            else:
                # 일반 HTTP (TODO: 구현 예정)
                logger.debug(f"[HTTP] 일반 HTTP 요청: {request_line.strip()}")
                # writer는 handle_client의 finally에서 정리됨

        except (asyncio.CancelledError, GeneratorExit):
            # 태스크 취소는 정상적인 종료 상황
            logger.debug(f"[Proxy] 클라이언트 연결 취소됨")
            raise  # CancelledError/GeneratorExit는 반드시 재발생시켜야 함
        except RuntimeError as e:
            if "GeneratorExit" in str(e):
                # GeneratorExit가 RuntimeError로 감싸진 경우 - 조용히 무시
                logger.debug(f"[Proxy] 클라이언트 연결 종료됨")
            else:
                logger.error(f"[Proxy] Runtime 오류: {e}")
                traceback.print_exc()
        except Exception as e:
            logger.error(f"[Proxy] 클라이언트 처리 오류: {e}")
            traceback.print_exc()
        finally:
            # 연결 정리 (Python 3.13+ asyncio 요구사항)
            try:
                if not writer.is_closing():
                    writer.close()
                    # wait_closed() 호출 필수 (Task pending 방지)
                    await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # 원격 호스트가 이미 연결을 끊은 경우 무시
                pass
            except Exception as e:
                logger.debug(f"[Proxy] Writer 정리 중 오류: {e}")

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
                # LLM 호스트: TLS 인터셉트
                logger.debug(f"[ROUTE] TLS 인터셉트 → {host}")
                await self.tls_interceptor.intercept(
                    reader, writer, host, port, self.http_handler
                )
            else:
                # 나머지: 투명 터널링
                logger.debug(f"[ROUTE] 투명 터널링 → {host}")
                await self.tunnel_handler.handle(reader, writer, host, port)

        except (asyncio.CancelledError, GeneratorExit):
            # 태스크 취소는 정상적인 종료 상황
            logger.debug(f"[CONNECT] 연결 취소됨: {host if 'host' in locals() else 'unknown'}")
            raise  # CancelledError/GeneratorExit는 반드시 재발생시켜야 함
        except RuntimeError as e:
            if "GeneratorExit" in str(e):
                # GeneratorExit가 RuntimeError로 감싸진 경우 - 조용히 무시
                logger.debug(f"[CONNECT] 연결 종료됨: {host if 'host' in locals() else 'unknown'}")
            else:
                logger.error(f"[CONNECT] Runtime 오류: {e}")
                traceback.print_exc()
                raise
        except Exception as e:
            logger.error(f"[CONNECT] 처리 오류: {e}")
            traceback.print_exc()
            raise  # 예외를 상위로 전파

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
