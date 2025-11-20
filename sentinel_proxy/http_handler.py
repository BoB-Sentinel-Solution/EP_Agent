#!/usr/bin/env python3
"""
HTTP 요청/응답 파싱 및 처리
mitmproxy HTTPFlow 객체 생성 및 addon 호출
"""
import asyncio
import logging
from typing import Optional, Tuple
from mitmproxy import http, connection

from sentinel_proxy.http_reader import read_http_request, read_http_response
from sentinel_proxy.http_parser import (
    parse_http_request, parse_http_response, get_header_value,
    remove_proxy_headers, rebuild_request_with_modified_body,
    rebuild_response_with_modified_body
)

logger = logging.getLogger(__name__)


class HTTPHandler:
    """HTTP 요청/응답 파싱 및 addon 통합"""

    def __init__(self, addon_instance, proxy_port: int):
        """
        Args:
            addon_instance: mitmproxy addon 인스턴스
            proxy_port: 프록시 포트
        """
        self.addon_instance = addon_instance
        self.proxy_port = proxy_port

    async def handle_http_exchange(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        first_request_sent: bool = False
    ):
        """
        HTTP 요청/응답 교환 처리 (Keep-Alive 지원)

        1. 클라이언트 → HTTP 요청 읽기 (raw bytes)
        2. HTTPFlow 생성 및 addon.request(flow) 호출
        3. 서버 → 요청 전송 (raw bytes)
        4. 서버 → 응답 수신 (raw bytes)
        5. addon.response(flow) 호출
        6. 클라이언트 → 응답 전송 (raw bytes)
        7. Keep-Alive 확인 → 반복 또는 종료
        """
        try:
            # HTTP/1.1 Keep-Alive 지원 (여러 요청 처리)
            request_count = 0
            max_requests = 100  # 최대 요청 수 제한

            while request_count < max_requests:
                request_count += 1

                # 1. HTTP 요청 읽기 (raw bytes)
                if first_request_sent and request_count == 1:
                    # 첫 번째 요청은 이미 서버로 전송됨 - 응답만 처리
                    request_data = None
                    logger.debug(f"[HTTP] 첫 번째 요청 스킵 (이미 전송됨)")
                else:
                    request_data = await read_http_request(client_reader)
                    if not request_data:
                        logger.debug(f"[HTTP] 연결 종료 (빈 요청) - {request_count-1}개 요청 처리됨")
                        break

                # 2. 요청 파싱 및 처리
                if request_data is not None:
                    # 일반적인 요청 처리
                    method, path, http_version, headers, body = parse_http_request(request_data)

                    # 파싱 검증
                    if not method or not path:
                        logger.warning(f"[HTTP] 잘못된 요청 파싱: method={method}, path={path}")
                        break

                    # 3. Connection 헤더 확인 (Keep-Alive 판단)
                    connection_header = get_header_value(headers, b'connection')
                    request_close = connection_header and b'close' in connection_header.lower()

                    # 4. mitmproxy HTTPFlow 객체 생성
                    try:
                        flow = self._create_http_flow(host, port, method, path, http_version, headers, body)
                    except ValueError as e:
                        logger.error(f"[HTTP] HTTPFlow 생성 실패: {e} | host={host}, path={path}")
                        break

                    # 5. addon.request(flow) 호출 (동기 호출 - GeneratorExit 문제 방지)
                    try:
                        self.addon_instance.request(flow)
                    except Exception as e:
                        logger.error(f"[HTTP] addon.request() 오류: {e}")

                    # 5-1. addon에서 content가 변조되었는지 확인
                    if flow.request.content != body:
                        # 변조됨 - HTTP 요청 재구성
                        logger.info(f"[HTTP] 패킷 변조 감지 - 요청 재구성 중... (원본: {len(body)} → 변조: {len(flow.request.content)} bytes)")
                        request_data = rebuild_request_with_modified_body(request_data, flow.request.content)
                        logger.info(f"[HTTP] 변조된 요청으로 재구성 완료")

                    # 6. 프록시 헤더 제거 (Cloudflare 차단 회피)
                    cleaned_request_data = remove_proxy_headers(request_data, host)

                    # 7. 서버로 요청 전송 (정제된 데이터)
                    server_writer.write(cleaned_request_data)
                    await server_writer.drain()
                else:
                    # 첫 번째 요청 스킵 - 기본값 설정
                    request_close = False

                # 8. 서버로부터 응답 읽기 (raw bytes)
                response_data = await read_http_response(server_reader)
                if not response_data:
                    logger.warning(f"[HTTP] 빈 응답 수신")
                    break

                # 9. 응답 파싱
                status_code, reason, resp_http_version, resp_headers, resp_body = parse_http_response(response_data)
                logger.debug(f"[HTTP] [{request_count}] {status_code} {reason} ({len(response_data)} bytes)")

                # 10. flow.response 설정
                flow.response = http.Response.make(
                    status_code=status_code,
                    content=resp_body,
                    headers=resp_headers
                )

                # 11. addon.response(flow) 호출 (동기 호출 - GeneratorExit 문제 방지)
                try:
                    self.addon_instance.response(flow)
                except Exception as e:
                    logger.error(f"[HTTP] addon.response() 오류: {e}")

                # 11-1. addon에서 응답이 변조되었는지 확인
                if flow.response.content != resp_body:
                    # 응답 변조됨 - HTTP 응답 재구성
                    logger.info(f"[HTTP] 응답 변조 감지 - 응답 재구성 중... (원본: {len(resp_body)} → 변조: {len(flow.response.content)} bytes)")
                    response_data = rebuild_response_with_modified_body(response_data, flow.response.content)
                    logger.info(f"[HTTP] 변조된 응답으로 재구성 완료")

                # 12. 클라이언트로 응답 전송
                client_writer.write(response_data)
                await client_writer.drain()

                # 13. Connection: close 확인 (Keep-Alive 종료 조건)
                response_connection = get_header_value(resp_headers, b'connection')
                response_close = response_connection and b'close' in response_connection.lower()

                if request_close or response_close:
                    logger.debug(f"[HTTP] Connection: close 감지, 연결 종료 ({request_count}개 요청 처리)")
                    break

            # Keep-Alive 루프 종료
            if request_count >= max_requests:
                logger.info(f"[HTTP] 최대 요청 수 도달 ({max_requests}), 연결 종료")

        except asyncio.CancelledError:
            logger.debug(f"[HTTP] HTTP 교환 취소됨")
            raise  # CancelledError는 반드시 재발생
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # 클라이언트 연결 종료 - 정상 상황
            logger.debug(f"[HTTP] 연결 오류 (정상): {e}")
        except Exception as e:
            logger.error(f"[HTTP] 교환 처리 오류: {e}")
            import traceback
            traceback.print_exc()

    def _create_http_flow(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        http_version: str,
        headers: list,
        body: bytes
    ) -> http.HTTPFlow:
        """
        mitmproxy HTTPFlow 객체 생성
        """
        # URL 구성
        scheme = "https" if port == 443 else "http"

        # HTTP/2 CONNECT 요청 처리 (path가 '*'인 경우)
        if path == '*' or path == '':
            path = '/'

        # 절대 경로가 아닌 경우 / 추가
        if not path.startswith('/'):
            path = '/' + path

        url = f"{scheme}://{host}{path}"

        # Request 객체 생성 (headers는 튜플 리스트로 직접 전달)
        request = http.Request.make(
            method=method,
            url=url,
            content=body,
            headers=headers
        )

        # Connection 객체 생성 (더미)
        client_conn = connection.Client(
            peername=("127.0.0.1", 0),
            sockname=("127.0.0.1", self.proxy_port),
            timestamp_start=0
        )

        server_conn = connection.Server(
            address=(host, port)
        )

        # HTTPFlow 생성
        flow = http.HTTPFlow(client_conn, server_conn)
        flow.request = request

        return flow
