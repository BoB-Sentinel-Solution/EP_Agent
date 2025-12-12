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

        try:
            logger.debug(f"[TLS] 인터셉트 시작: {host}:{port}")

            # 1. 캐시 확인 (디스크 I/O 최소화)
            if host in self.tls_cache:
                cached = self.tls_cache[host]
                cert_path = cached['cert_path']
                key_path = cached['key_path']
                client_ssl_context = cached['ssl_context']

                # ALPN이 설정되지 않은 이전 캐시 처리
                if not hasattr(client_ssl_context, '_alpn_protocols') or client_ssl_context._alpn_protocols is None:
                    client_ssl_context.set_alpn_protocols(['http/1.1'])
                    logger.debug(f"[TLS] 캐시된 context에 ALPN 추가: {host}")

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

                # ALPN 설정 (HTTP/1.1 강제)
                client_ssl_context.set_alpn_protocols(['http/1.1'])
                logger.debug(f"[TLS] ALPN 설정: http/1.1")

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
            try:
                new_transport = await loop.start_tls(
                    transport,
                    protocol,
                    client_ssl_context,
                    server_side=True,
                    ssl_handshake_timeout=10
                )
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.debug(f"[TLS] 클라이언트 TLS 핸드셰이크 실패 ({host}): {e}")
                return

            # 새로운 writer 생성
            ssl_writer = asyncio.StreamWriter(new_transport, protocol, ssl_reader, loop)

            # ALPN 협상 결과 확인
            negotiated_protocol = new_transport.get_extra_info('ssl_object').selected_alpn_protocol()
            logger.info(f"[TLS] 클라이언트 TLS 핸드셰이크 완료 - ALPN: {negotiated_protocol}")

            # 5. 실제 서버와 연결
            upstream_reader, upstream_writer = await asyncio.open_connection(
                host, port, ssl=True
            )
            logger.debug(f"[TLS] 업스트림 서버 연결 완료: {host}:{port}")

            # 6. HTTP 요청/응답 처리
            await http_handler.handle_http_exchange(
                ssl_reader, ssl_writer,
                upstream_reader, upstream_writer,
                host, port
            )

        except (asyncio.CancelledError, GeneratorExit):
            logger.debug(f"[TLS] 인터셉트 취소됨: {host}:{port}")
            raise  # CancelledError/GeneratorExit는 반드시 재발생시켜야 함
        except RuntimeError as e:
            if "GeneratorExit" in str(e):
                # GeneratorExit가 RuntimeError로 감싸진 경우 - 조용히 무시
                logger.debug(f"[TLS] 연결 종료됨: {host}:{port}")
            else:
                logger.error(f"[TLS] Runtime 오류 ({host}:{port}): {e}")
                traceback.print_exc()
        except Exception as e:
            logger.error(f"[TLS] 인터셉트 오류 ({host}:{port}): {e}")
            traceback.print_exc()

        finally:
            # 임시 파일은 캐시로 관리되므로 삭제하지 않음 (성능 최적화)
            # 캐시 LRU에서 제거될 때만 파일 삭제됨

            # 업스트림 연결만 정리 (클라이언트 writer는 handle_client에서 정리)
            try:
                if upstream_writer and not upstream_writer.is_closing():
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # 원격 호스트가 이미 연결을 끊은 경우 무시
                pass
            except Exception as e:
                logger.debug(f"[TLS] 업스트림 Writer 정리 중 오류: {e}")

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
