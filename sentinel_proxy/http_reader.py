#!/usr/bin/env python3
"""
HTTP 비동기 읽기 모듈
"""
import asyncio
import logging

logger = logging.getLogger(__name__)


async def read_http_request(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """HTTP 요청 읽기 (Content-Length 기반)"""
    try:
        request_data = b''
        content_length = None
        headers_received = False

        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break

            if not chunk:
                break
            request_data += chunk

            if not headers_received and b'\r\n\r\n' in request_data:
                headers_received = True
                headers_end = request_data.find(b'\r\n\r\n')
                headers = request_data[:headers_end]

                for line in headers.split(b'\r\n'):
                    if line.lower().startswith(b'content-length:'):
                        try:
                            content_length = int(line.split(b':')[1].strip())
                        except:
                            pass
                        break

            if headers_received:
                if content_length is not None:
                    headers_end = request_data.find(b'\r\n\r\n')
                    body_start = headers_end + 4
                    body = request_data[body_start:]
                    if len(body) >= content_length:
                        request_data = request_data[:body_start + content_length]
                        break
                else:
                    break

        return request_data

    except Exception as e:
        logger.error(f"[HTTP] 요청 읽기 오류: {e}")
        return b''


async def read_http_response(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """HTTP 응답 읽기 (Content-Length 및 chunked 지원)"""
    try:
        response_data = b''
        content_length = None
        is_chunked = False
        headers_received = False

        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break

            if not chunk:
                break
            response_data += chunk

            if not headers_received and b'\r\n\r\n' in response_data:
                headers_received = True
                headers_end = response_data.find(b'\r\n\r\n')
                headers = response_data[:headers_end]

                for line in headers.split(b'\r\n'):
                    lower_line = line.lower()
                    if lower_line.startswith(b'content-length:'):
                        try:
                            content_length = int(line.split(b':')[1].strip())
                        except:
                            pass
                    elif lower_line.startswith(b'transfer-encoding:') and b'chunked' in lower_line:
                        is_chunked = True

            if headers_received and content_length is not None:
                headers_end = response_data.find(b'\r\n\r\n')
                body_start = headers_end + 4
                body = response_data[body_start:]
                if len(body) >= content_length:
                    response_data = response_data[:body_start + content_length]
                    break

            if headers_received and is_chunked:
                if b'\r\n0\r\n\r\n' in response_data or response_data.endswith(b'0\r\n\r\n'):
                    break

            if headers_received and content_length is None and not is_chunked:
                break

        return response_data

    except Exception as e:
        logger.error(f"[HTTP] 응답 읽기 오류: {e}")
        return b''
