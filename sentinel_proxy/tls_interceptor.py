#!/usr/bin/env python3
"""
TLS 인터셉터 - LLM 호스트에 대한 TLS 인터셉트
"""
import asyncio
import ssl
import tempfile
import logging
import traceback
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class TLSInterceptor:
    """TLS 인터셉터 - Sentinel CA로 HTTPS 트래픽 복호화"""

    def __init__(self, cert_manager):
        """
        Args:
            cert_manager: CertificateManager 인스턴스
        """
        self.cert_manager = cert_manager

        # SSL Context + 임시 파일 경로 캐싱 (디스크 I/O 최소화)
        self.tls_cache = {}  # {hostname: {'cert_path': Path, 'key_path': Path, 'ssl_context': SSLContext}}
        self.tls_cache_max = 100

    async def intercept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        http_handler
    ):
        """
        TLS 인터셉트 및 HTTP 처리

        Args:
            reader: 클라이언트 reader
            writer: 클라이언트 writer
            host: 목적지 호스트
            port: 목적지 포트
            http_handler: HTTPHandler 인스턴스
        """
        upstream_reader = None
        upstream_writer = None
        ssl_writer = None

        try:
            logger.debug(f"[TLS] 인터셉트 시작: {host}:{port}")

            # 1. 캐시 확인 (디스크 I/O 최소화)
            if host in self.tls_cache:
                cached = self.tls_cache[host]
                cert_path = cached['cert_path']
                key_path = cached['key_path']
                client_ssl_context = cached['ssl_context']
                logger.debug(f"[TLS] 캐시에서 인증서 재사용: {host}")
            else:
                # 2. 대상 호스트용 서버 인증서 생성 (캐시 없음)
                cert_pem, key_pem = self.cert_manager.generate_server_certificate(host)

                # 3. 임시 파일로 저장 (SSL context가 파일 경로 필요)
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                    cert_file.write(cert_pem)
                    cert_path = cert_file.name

                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                    key_file.write(key_pem)
                    key_path = key_file.name

                # 4. SSL context 생성 (클라이언트 연결용)
                client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                client_ssl_context.load_cert_chain(cert_path, key_path)
                client_ssl_context.check_hostname = False
                client_ssl_context.verify_mode = ssl.CERT_NONE

                # 5. 캐시에 저장 (LRU)
                if len(self.tls_cache) >= self.tls_cache_max:
                    # 가장 오래된 항목 제거 및 임시 파일 삭제
                    oldest_host = next(iter(self.tls_cache))
                    oldest_cached = self.tls_cache.pop(oldest_host)
                    try:
                        os.unlink(oldest_cached['cert_path'])
                        os.unlink(oldest_cached['key_path'])
                    except:
                        pass
                    logger.debug(f"[TLS] 캐시 가득참, 제거: {oldest_host}")

                self.tls_cache[host] = {
                    'cert_path': cert_path,
                    'key_path': key_path,
                    'ssl_context': client_ssl_context
                }
                logger.info(f"[TLS] 인증서 생성 및 캐싱 완료: {host} (캐시 크기: {len(self.tls_cache)}/{self.tls_cache_max})")

            # 4. StreamReader/Writer를 TLS로 업그레이드
            loop = asyncio.get_running_loop()

            # 새로운 프로토콜 생성
            ssl_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(ssl_reader)

            # TLS 전송 시작
            transport = writer.transport
            logger.debug(f"[TLS] TLS 핸드셰이크 시작: {host}")
            try:
                new_transport = await asyncio.wait_for(
                    loop.start_tls(
                        transport,
                        protocol,
                        client_ssl_context,
                        server_side=True,
                        ssl_handshake_timeout=10
                    ),
                    timeout=15.0  # 전체 타임아웃 15초
                )
                logger.debug(f"[TLS] start_tls 완료: {host}")
            except asyncio.TimeoutError:
                logger.warning(f"[TLS] 클라이언트 TLS 핸드셰이크 타임아웃 ({host})")
                return
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.warning(f"[TLS] 클라이언트 TLS 핸드셰이크 실패 ({host}): {type(e).__name__} - {e}")
                return
            except asyncio.CancelledError:
                logger.debug(f"[TLS] TLS 핸드셰이크 취소됨 ({host})")
                raise  # CancelledError는 반드시 재발생
            except Exception as e:
                # 예상치 못한 예외 (GeneratorExit 등)
                logger.error(f"[TLS] TLS 핸드셰이크 예외 ({host}): {type(e).__name__} - {e}")
                import traceback
                traceback.print_exc()
                raise  # 모든 예외 재발생

            # 새로운 writer 생성
            ssl_writer = asyncio.StreamWriter(new_transport, protocol, ssl_reader, loop)

            logger.debug(f"[TLS] 클라이언트 TLS 핸드셰이크 완료")

            # 5. 실제 서버와 연결
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=True),
                    timeout=10.0  # 업스트림 연결 타임아웃 10초
                )
                logger.debug(f"[TLS] 업스트림 서버 연결 완료: {host}:{port}")
            except asyncio.TimeoutError:
                logger.debug(f"[TLS] 업스트림 서버 연결 타임아웃: {host}:{port}")
                return
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.debug(f"[TLS] 업스트림 서버 연결 실패: {host}:{port} - {e}")
                return
            except asyncio.CancelledError:
                logger.debug(f"[TLS] 업스트림 연결 취소됨: {host}:{port}")
                raise  # CancelledError는 반드시 재발생
            except Exception as e:
                # 예상치 못한 예외
                logger.error(f"[TLS] 업스트림 연결 예외 ({host}:{port}): {type(e).__name__} - {e}")
                raise  # 모든 예외 재발생

            # 6. HTTP 요청/응답 처리
            try:
                await http_handler.handle_http_exchange(
                    ssl_reader, ssl_writer,
                    upstream_reader, upstream_writer,
                    host, port
                )
            except asyncio.CancelledError:
                logger.debug(f"[TLS] HTTP 교환 취소됨: {host}:{port}")
                raise  # CancelledError는 반드시 재발생

        except asyncio.CancelledError:
            logger.debug(f"[TLS] 인터셉트 취소됨: {host}:{port}")
            raise  # CancelledError는 반드시 재발생
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug(f"[TLS] 연결 오류 (정상): {host}:{port} - {e}")
        except Exception as e:
            logger.error(f"[TLS] 인터셉트 오류 ({host}:{port}): {e}")
            import traceback
            traceback.print_exc()

        finally:
            # 업스트림 연결 정리
            await self._safe_close_upstream(upstream_writer, f"{host}:{port}")

            # ssl_writer 정리 (TLS로 업그레이드된 클라이언트 연결)
            if ssl_writer and not ssl_writer.is_closing():
                try:
                    ssl_writer.close()
                    # SSL 에러 무시하고 정리
                    try:
                        await asyncio.wait_for(ssl_writer.wait_closed(), timeout=1.0)
                    except (ssl.SSLError, asyncio.TimeoutError):
                        pass  # SSL 종료 에러는 무시
                    logger.debug(f"[TLS] SSL Writer 정리 완료: {host}:{port}")
                except Exception as e:
                    logger.debug(f"[TLS] SSL Writer 정리 중 오류: {host}:{port} - {e}")

    async def _safe_close_upstream(self, upstream_writer, connection_info):
        """업스트림 Writer 안전 정리"""
        try:
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                try:
                    await asyncio.wait_for(upstream_writer.wait_closed(), timeout=2.0)
                    logger.debug(f"[TLS] 업스트림 정리 완료: {connection_info}")
                except (ssl.SSLError, asyncio.TimeoutError):
                    # SSL 에러 및 타임아웃은 무시
                    logger.debug(f"[TLS] 업스트림 정리 (SSL 에러 무시): {connection_info}")
                except Exception as e:
                    logger.debug(f"[TLS] 업스트림 wait_closed 오류: {connection_info} - {e}")
        except Exception as e:
            logger.debug(f"[TLS] 업스트림 정리 중 오류: {connection_info} - {e}")

    def cleanup(self):
        """프로그램 종료 시 캐시된 임시 파일 정리"""
        logger.info(f"[TLS] 캐시된 임시 파일 정리 중... ({len(self.tls_cache)}개)")
        for host, cached in self.tls_cache.items():
            try:
                os.unlink(cached['cert_path'])
                os.unlink(cached['key_path'])
                logger.debug(f"[TLS] 임시 파일 삭제: {host}")
            except Exception as e:
                logger.warning(f"[TLS] 임시 파일 삭제 실패 ({host}): {e}")
        self.tls_cache.clear()
        logger.info("[TLS] 캐시 정리 완료")
