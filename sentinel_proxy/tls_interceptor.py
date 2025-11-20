#!/usr/bin/env python3
"""
TLS 인터셉터 - LLM 호스트에 대한 TLS 인터셉트
"""
import asyncio
import ssl
import tempfile
import logging
import os

from sentinel_proxy.utils import safe_close_writer, open_upstream_connection

logger = logging.getLogger(__name__)


class TLSInterceptor:
    """TLS 인터셉터 - Sentinel CA로 HTTPS 트래픽 복호화"""

    def __init__(self, cert_manager):
        self.cert_manager = cert_manager
        self.tls_cache = {}  # {hostname: {'cert_path', 'key_path', 'ssl_context'}}
        self.tls_cache_max = 100

    async def intercept(self, reader, writer, host: str, port: int, http_handler):
        """TLS 인터셉트 및 HTTP 처리"""
        upstream_writer = None
        ssl_writer = None

        try:
            logger.debug(f"[TLS] 인터셉트 시작: {host}:{port}")

            # 1. SSL Context 가져오기 (캐시 또는 생성)
            client_ssl_context = self._get_ssl_context(host)

            # 2. 클라이언트 TLS 업그레이드
            ssl_reader, ssl_writer = await self._upgrade_client_tls(writer, client_ssl_context, host)
            if not ssl_reader:
                return

            # 3. 업스트림 서버 연결
            upstream_reader, upstream_writer = await open_upstream_connection(host, port, use_ssl=True)
            if not upstream_reader:
                return

            # 4. HTTP 요청/응답 처리
            try:
                await http_handler.handle_http_exchange(
                    ssl_reader, ssl_writer,
                    upstream_reader, upstream_writer,
                    host, port
                )
            except asyncio.CancelledError:
                logger.debug(f"[TLS] HTTP 교환 취소됨: {host}:{port}")
                raise

        except asyncio.CancelledError:
            logger.debug(f"[TLS] 인터셉트 취소됨: {host}:{port}")
            raise
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug(f"[TLS] 연결 오류: {host}:{port} - {e}")
        except Exception as e:
            logger.error(f"[TLS] 인터셉트 오류: {host}:{port} - {e}")
            import traceback
            traceback.print_exc()
        finally:
            await safe_close_writer(upstream_writer, f"{host}:{port}")
            await safe_close_writer(ssl_writer, f"{host}:{port}", timeout=1.0)

    def _get_ssl_context(self, host: str):
        """SSL Context 가져오기 (캐시 또는 생성)"""
        if host in self.tls_cache:
            logger.debug(f"[TLS] 캐시에서 인증서 재사용: {host}")
            return self.tls_cache[host]['ssl_context']

        # 인증서 생성
        cert_pem, key_pem = self.cert_manager.generate_server_certificate(host)

        # 임시 파일 저장
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as f:
            f.write(cert_pem)
            cert_path = f.name

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as f:
            f.write(key_pem)
            key_path = f.name

        # SSL Context 생성
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # 캐시 관리 (LRU)
        if len(self.tls_cache) >= self.tls_cache_max:
            oldest = next(iter(self.tls_cache))
            old = self.tls_cache.pop(oldest)
            try:
                os.unlink(old['cert_path'])
                os.unlink(old['key_path'])
            except:
                pass

        self.tls_cache[host] = {
            'cert_path': cert_path,
            'key_path': key_path,
            'ssl_context': ssl_context
        }
        logger.info(f"[TLS] 인증서 생성: {host} ({len(self.tls_cache)}/{self.tls_cache_max})")

        return ssl_context

    async def _upgrade_client_tls(self, writer, ssl_context, host: str):
        """클라이언트 연결을 TLS로 업그레이드"""
        try:
            loop = asyncio.get_running_loop()
            ssl_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(ssl_reader)

            transport = writer.transport
            new_transport = await asyncio.wait_for(
                loop.start_tls(
                    transport, protocol, ssl_context,
                    server_side=True, ssl_handshake_timeout=10
                ),
                timeout=15.0
            )

            ssl_writer = asyncio.StreamWriter(new_transport, protocol, ssl_reader, loop)
            logger.debug(f"[TLS] 클라이언트 TLS 핸드셰이크 완료: {host}")
            return ssl_reader, ssl_writer

        except asyncio.TimeoutError:
            logger.warning(f"[TLS] TLS 핸드셰이크 타임아웃: {host}")
            return None, None
        except asyncio.CancelledError:
            logger.debug(f"[TLS] TLS 핸드셰이크 취소됨: {host}")
            raise
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.warning(f"[TLS] TLS 핸드셰이크 실패: {host} - {e}")
            return None, None
        except Exception as e:
            logger.error(f"[TLS] TLS 핸드셰이크 예외: {host} - {e}")
            return None, None

    def cleanup(self):
        """프로그램 종료 시 캐시된 임시 파일 정리"""
        logger.info(f"[TLS] 캐시 정리 중... ({len(self.tls_cache)}개)")
        for host, cached in self.tls_cache.items():
            try:
                os.unlink(cached['cert_path'])
                os.unlink(cached['key_path'])
            except:
                pass
        self.tls_cache.clear()
        logger.info("[TLS] 정리 완료")
