#!/usr/bin/env python3
"""
HTTP 요청/응답 파싱 및 처리
mitmproxy HTTPFlow 객체 생성 및 addon 호출
"""
import asyncio
import logging
import traceback
from typing import Optional, Tuple
from mitmproxy import http, connection

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
        port: int
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
                request_data = await self._read_http_request(client_reader)
                if not request_data:
                    logger.debug(f"[HTTP] 연결 종료 (빈 요청) - {request_count-1}개 요청 처리됨")
                    break

                # 2. 요청 파싱
                method, path, http_version, headers, body = self._parse_http_request_bytes(request_data)
                logger.debug(f"[HTTP] [{request_count}] {method} {path}")

                # 3. Connection 헤더 확인 (Keep-Alive 판단)
                connection_header = self._get_header_value(headers, b'connection')
                request_close = connection_header and b'close' in connection_header.lower()

                # 4. mitmproxy HTTPFlow 객체 생성
                flow = self._create_http_flow(host, port, method, path, http_version, headers, body)

                # 5. addon.request(flow) 호출
                try:
                    await asyncio.to_thread(self.addon_instance.request, flow)
                except Exception as e:
                    logger.error(f"[HTTP] addon.request() 오류: {e}")

                # 6. 프록시 헤더 제거 (Cloudflare 차단 회피)
                cleaned_request_data = self._remove_proxy_headers(request_data, host)

                # 7. 서버로 요청 전송 (정제된 데이터)
                server_writer.write(cleaned_request_data)
                await server_writer.drain()

                # 8. 서버로부터 응답 읽기 (raw bytes)
                response_data = await self._read_http_response(server_reader)
                if not response_data:
                    logger.warning(f"[HTTP] 빈 응답 수신")
                    break

                # 9. 응답 파싱
                status_code, reason, resp_http_version, resp_headers, resp_body = self._parse_http_response_bytes(response_data)
                logger.debug(f"[HTTP] [{request_count}] {status_code} {reason} ({len(response_data)} bytes)")

                # 10. flow.response 설정
                flow.response = http.Response.make(
                    status_code=status_code,
                    content=resp_body,
                    headers=resp_headers
                )

                # 11. addon.response(flow) 호출
                try:
                    await asyncio.to_thread(self.addon_instance.response, flow)
                except Exception as e:
                    logger.error(f"[HTTP] addon.response() 오류: {e}")

                # 12. 클라이언트로 응답 전송 (원본 데이터 그대로)
                client_writer.write(response_data)
                await client_writer.drain()

                # 13. Connection: close 확인 (Keep-Alive 종료 조건)
                response_connection = self._get_header_value(resp_headers, b'connection')
                response_close = response_connection and b'close' in response_connection.lower()

                if request_close or response_close:
                    logger.debug(f"[HTTP] Connection: close 감지, 연결 종료 ({request_count}개 요청 처리)")
                    break

            # Keep-Alive 루프 종료
            if request_count >= max_requests:
                logger.info(f"[HTTP] 최대 요청 수 도달 ({max_requests}), 연결 종료")

        except (asyncio.CancelledError, GeneratorExit):
            logger.debug(f"[HTTP] HTTP 교환 취소됨")
            raise
        except (ConnectionResetError, BrokenPipeError) as e:
            # 클라이언트 연결 종료 - 정상 상황
            logger.debug(f"[HTTP] 클라이언트 연결 종료: {e}")
        except RuntimeError as e:
            if "GeneratorExit" in str(e):
                # GeneratorExit가 RuntimeError로 감싸진 경우 - 조용히 무시
                logger.debug(f"[HTTP] HTTP 교환 종료됨")
            else:
                logger.error(f"[HTTP] Runtime 오류: {e}")
                traceback.print_exc()
        except Exception as e:
            logger.error(f"[HTTP] 교환 처리 오류: {e}")
            traceback.print_exc()

    async def _read_http_request(self, reader: asyncio.StreamReader) -> bytes:
        """HTTP 요청 읽기 (Content-Length 기반)"""
        try:
            request_data = b''
            content_length = None
            headers_received = False

            while True:
                chunk = await reader.read(8192)
                if not chunk:
                    break
                request_data += chunk

                # 헤더 끝 감지
                if not headers_received and b'\r\n\r\n' in request_data:
                    headers_received = True
                    headers_end = request_data.find(b'\r\n\r\n')
                    headers = request_data[:headers_end]

                    # Content-Length 확인
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-length:'):
                            try:
                                content_length = int(line.split(b':')[1].strip())
                            except:
                                pass
                            break

                # Content-Length가 있으면 정확한 크기만큼 읽기
                if headers_received:
                    if content_length is not None:
                        body_start = headers_end + 4
                        body = request_data[body_start:]
                        if len(body) >= content_length:
                            break
                    else:
                        # Content-Length 없으면 헤더만 읽고 종료
                        break

            return request_data

        except Exception as e:
            logger.error(f"[HTTP] 요청 읽기 오류: {e}")
            return b''

    async def _read_http_response(self, reader: asyncio.StreamReader) -> bytes:
        """HTTP 응답 읽기 (Content-Length 및 chunked encoding 지원)"""
        try:
            response_data = b''
            content_length = None
            is_chunked = False
            headers_received = False

            while True:
                chunk = await reader.read(8192)
                if not chunk:
                    break
                response_data += chunk

                # 헤더 분석
                if not headers_received and b'\r\n\r\n' in response_data:
                    headers_received = True
                    headers_end = response_data.find(b'\r\n\r\n')
                    headers = response_data[:headers_end]

                    # Content-Length 및 Transfer-Encoding 확인
                    for line in headers.split(b'\r\n'):
                        lower_line = line.lower()
                        if lower_line.startswith(b'content-length:'):
                            try:
                                content_length = int(line.split(b':')[1].strip())
                            except:
                                pass
                        elif lower_line.startswith(b'transfer-encoding:') and b'chunked' in lower_line:
                            is_chunked = True

                # Content-Length가 있으면 정확한 크기만큼 읽기
                if headers_received and content_length is not None:
                    body_start = headers_end + 4
                    body = response_data[body_start:]
                    if len(body) >= content_length:
                        break

                # Chunked encoding인 경우 마지막 청크 확인
                if headers_received and is_chunked:
                    if b'\r\n0\r\n\r\n' in response_data or response_data.endswith(b'0\r\n\r\n'):
                        break

                # 헤더만 있고 body 없는 경우
                if headers_received and content_length is None and not is_chunked:
                    break

            return response_data

        except Exception as e:
            logger.error(f"[HTTP] 응답 읽기 오류: {e}")
            return b''

    def _parse_http_request_bytes(self, request_data: bytes) -> Tuple:
        """HTTP 요청 파싱 (raw bytes → 튜플)"""
        try:
            # 헤더와 바디 분리
            if b'\r\n\r\n' in request_data:
                headers_end = request_data.find(b'\r\n\r\n')
                headers_section = request_data[:headers_end]
                body = request_data[headers_end + 4:]
            else:
                headers_section = request_data
                body = b''

            # 첫 줄 파싱
            lines = headers_section.split(b'\r\n')
            first_line = lines[0].decode('utf-8', errors='ignore')
            parts = first_line.split(' ')
            if len(parts) >= 3:
                method, path, http_version = parts[0], parts[1], parts[2]
            else:
                method, path, http_version = 'GET', '/', 'HTTP/1.1'

            # 헤더 파싱 (바이트 튜플 리스트)
            headers = []
            for line in lines[1:]:
                if line and b':' in line:
                    key, value = line.split(b':', 1)
                    headers.append((key.strip(), value.strip()))

            return (method, path, http_version, headers, body)

        except Exception as e:
            logger.error(f"[HTTP] 요청 파싱 오류: {e}")
            return ('GET', '/', 'HTTP/1.1', [], b'')

    def _parse_http_response_bytes(self, response_data: bytes) -> Tuple:
        """HTTP 응답 파싱 (raw bytes → 튜플)"""
        try:
            # 헤더와 바디 분리
            if b'\r\n\r\n' in response_data:
                headers_end = response_data.find(b'\r\n\r\n')
                headers_section = response_data[:headers_end]
                body = response_data[headers_end + 4:]
            else:
                headers_section = response_data
                body = b''

            # 상태 라인 파싱
            lines = headers_section.split(b'\r\n')
            status_line = lines[0].decode('utf-8', errors='ignore')
            parts = status_line.split(' ', 2)
            if len(parts) >= 3:
                http_version, status_code, reason = parts[0], int(parts[1]), parts[2]
            elif len(parts) == 2:
                http_version, status_code, reason = parts[0], int(parts[1]), 'OK'
            else:
                http_version, status_code, reason = 'HTTP/1.1', 200, 'OK'

            # 헤더 파싱 (바이트 튜플 리스트)
            headers = []
            for line in lines[1:]:
                if line and b':' in line:
                    key, value = line.split(b':', 1)
                    headers.append((key.strip(), value.strip()))

            return (status_code, reason, http_version, headers, body)

        except Exception as e:
            logger.error(f"[HTTP] 응답 파싱 오류: {e}")
            return (200, 'OK', 'HTTP/1.1', [], b'')

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

    def _remove_proxy_headers(self, request_data: bytes, host: str) -> bytes:
        """
        프록시 관련 헤더 제거 (Cloudflare 차단 회피)

        Args:
            request_data: 원본 HTTP 요청 데이터
            host: 대상 호스트

        Returns:
            정제된 HTTP 요청 데이터
        """
        try:
            # 헤더와 바디 분리
            if b'\r\n\r\n' not in request_data:
                return request_data

            headers_end = request_data.find(b'\r\n\r\n')
            headers_section = request_data[:headers_end]
            body = request_data[headers_end + 4:]

            # 줄 단위로 분리
            lines = headers_section.split(b'\r\n')
            first_line = lines[0]  # 요청 라인 유지

            # 제거할 헤더 목록
            proxy_headers = [
                b'proxy-connection',
                b'x-forwarded-for',
                b'x-forwarded-host',
                b'x-forwarded-proto',
                b'forwarded',
                b'via',
                b'x-real-ip',
                b'x-proxy-id'
            ]

            # 헤더 필터링
            cleaned_headers = [first_line]
            for line in lines[1:]:
                if not line or b':' not in line:
                    continue

                key = line.split(b':', 1)[0].strip().lower()

                # 프록시 관련 헤더 제거
                if key in proxy_headers:
                    continue

                cleaned_headers.append(line)

            # 재조립
            cleaned_request = b'\r\n'.join(cleaned_headers) + b'\r\n\r\n' + body
            return cleaned_request

        except Exception as e:
            logger.warning(f"[HTTP] 헤더 정제 실패: {e}, 원본 전송")
            return request_data

    def _get_header_value(self, headers: list, header_name: bytes) -> Optional[bytes]:
        """
        헤더 목록에서 특정 헤더 값 추출

        Args:
            headers: 헤더 튜플 리스트 [(key, value), ...]
            header_name: 찾을 헤더 이름 (소문자)

        Returns:
            헤더 값 또는 None
        """
        for key, value in headers:
            if key.lower() == header_name.lower():
                return value
        return None
