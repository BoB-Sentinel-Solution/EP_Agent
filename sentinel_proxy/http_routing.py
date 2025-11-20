#!/usr/bin/env python3
"""
HTTP 라우팅 및 요청 처리 모듈
"""
import asyncio
import logging
from sentinel_proxy.utils import safe_close_writer, relay_data, open_upstream_connection

logger = logging.getLogger(__name__)


def parse_request_line(request_line: str):
    """HTTP 요청 라인 파싱 → (method, url, http_version) 또는 None"""
    parts = request_line.strip().split()
    if len(parts) < 3:
        return None
    return parts[0], parts[1], parts[2]


def extract_host_from_url(url: str):
    """URL에서 호스트 추출 → (host, port, path) 또는 None"""
    if url.startswith('http://'):
        url_without_scheme = url[7:]
        if '/' in url_without_scheme:
            host_port, path = url_without_scheme.split('/', 1)
            path = '/' + path
        else:
            host_port = url_without_scheme
            path = '/'

        if ':' in host_port:
            host, port_str = host_port.rsplit(':', 1)
            return host, int(port_str), path
        else:
            return host_port, 80, path
    elif url.startswith('/'):
        return None, None, url
    else:
        return None


async def read_remaining_headers(reader: asyncio.StreamReader, first_line: str):
    """나머지 헤더와 body 읽기"""
    headers_data = first_line.encode('utf-8')

    while True:
        line = await reader.readline()
        if not line or line == b'\r\n' or line == b'\n':
            headers_data += line
            break
        headers_data += line

    # Content-Length 확인 및 body 읽기
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

    return headers_data + body


async def extract_host_from_headers(reader: asyncio.StreamReader):
    """Host 헤더에서 호스트 정보 추출"""
    try:
        while True:
            line = await reader.readline()
            if not line or line == b'\r\n' or line == b'\n':
                break

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


async def handle_http_with_security(full_request: bytes, client_reader, client_writer,
                                   host: str, port: int, http_version: str, http_handler):
    """보안 엔진을 통한 HTTP 처리"""
    server_reader, server_writer = await open_upstream_connection(host, port)
    if not server_reader:
        error_response = f"{http_version} 502 Bad Gateway\r\nConnection: close\r\n\r\nConnection Failed".encode()
        client_writer.write(error_response)
        await client_writer.drain()
        return

    try:
        server_writer.write(full_request)
        await server_writer.drain()
        await http_handler.handle_http_exchange(
            client_reader, client_writer, server_reader, server_writer,
            host, port, first_request_sent=True
        )
    except Exception as e:
        logger.error(f"[HTTP] 보안 처리 오류: {e}")
    finally:
        await safe_close_writer(server_writer, f"{host}:{port}")


async def handle_http_proxy(full_request: bytes, client_reader, client_writer, host: str, port: int):
    """직접 HTTP 프록싱 (보안 처리 없음)"""
    server_reader, server_writer = await open_upstream_connection(host, port)
    if not server_reader:
        error_response = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nConnection Failed"
        client_writer.write(error_response)
        await client_writer.drain()
        return

    try:
        server_writer.write(full_request)
        await server_writer.drain()
        await asyncio.gather(
            relay_data(client_reader, server_writer, f"C→{host}"),
            relay_data(server_reader, client_writer, f"{host}→C")
        )
    except Exception as e:
        logger.error(f"[HTTP] 직접 프록싱 오류: {e}")
    finally:
        await safe_close_writer(server_writer, f"{host}:{port}")
