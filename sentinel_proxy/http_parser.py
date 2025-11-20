#!/usr/bin/env python3
"""
HTTP 파싱 유틸리티 모듈
"""
import re
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)


def parse_http_request(request_data: bytes) -> Tuple[str, str, str, list, bytes]:
    """HTTP 요청 파싱 → (method, path, http_version, headers, body)"""
    try:
        if b'\r\n\r\n' in request_data:
            headers_end = request_data.find(b'\r\n\r\n')
            headers_section = request_data[:headers_end]
            body = request_data[headers_end + 4:]
        else:
            headers_section = request_data
            body = b''

        lines = headers_section.split(b'\r\n')
        first_line = lines[0].decode('utf-8', errors='ignore')
        parts = first_line.split(' ')
        if len(parts) >= 3:
            method, path, http_version = parts[0], parts[1], parts[2]
        else:
            method, path, http_version = 'GET', '/', 'HTTP/1.1'

        headers = []
        for line in lines[1:]:
            if line and b':' in line:
                key, value = line.split(b':', 1)
                headers.append((key.strip(), value.strip()))

        return (method, path, http_version, headers, body)

    except Exception as e:
        logger.error(f"[HTTP] 요청 파싱 오류: {e}")
        return ('GET', '/', 'HTTP/1.1', [], b'')


def parse_http_response(response_data: bytes) -> Tuple[int, str, str, list, bytes]:
    """HTTP 응답 파싱 → (status_code, reason, http_version, headers, body)"""
    try:
        if b'\r\n\r\n' in response_data:
            headers_end = response_data.find(b'\r\n\r\n')
            headers_section = response_data[:headers_end]
            body = response_data[headers_end + 4:]
        else:
            headers_section = response_data
            body = b''

        lines = headers_section.split(b'\r\n')
        status_line = lines[0].decode('utf-8', errors='ignore')
        parts = status_line.split(' ', 2)
        if len(parts) >= 3:
            http_version, status_code, reason = parts[0], int(parts[1]), parts[2]
        elif len(parts) == 2:
            http_version, status_code, reason = parts[0], int(parts[1]), 'OK'
        else:
            http_version, status_code, reason = 'HTTP/1.1', 200, 'OK'

        headers = []
        for line in lines[1:]:
            if line and b':' in line:
                key, value = line.split(b':', 1)
                headers.append((key.strip(), value.strip()))

        return (status_code, reason, http_version, headers, body)

    except Exception as e:
        logger.error(f"[HTTP] 응답 파싱 오류: {e}")
        return (200, 'OK', 'HTTP/1.1', [], b'')


def get_header_value(headers: list, header_name: bytes) -> Optional[bytes]:
    """헤더 목록에서 특정 헤더 값 추출"""
    for key, value in headers:
        if key.lower() == header_name.lower():
            return value
    return None


def remove_proxy_headers(request_data: bytes, host: str) -> bytes:
    """프록시 관련 헤더 제거"""
    try:
        if b'\r\n\r\n' not in request_data:
            return request_data

        headers_end = request_data.find(b'\r\n\r\n')
        headers_section = request_data[:headers_end]
        body = request_data[headers_end + 4:]

        lines = headers_section.split(b'\r\n')
        first_line = lines[0]

        proxy_headers = [
            b'proxy-connection', b'x-forwarded-for', b'x-forwarded-host',
            b'x-forwarded-proto', b'forwarded', b'via', b'x-real-ip', b'x-proxy-id'
        ]

        cleaned_headers = [first_line]
        for line in lines[1:]:
            if not line or b':' not in line:
                continue
            key = line.split(b':', 1)[0].strip().lower()
            if key not in proxy_headers:
                cleaned_headers.append(line)

        return b'\r\n'.join(cleaned_headers) + b'\r\n\r\n' + body

    except Exception as e:
        logger.warning(f"[HTTP] 헤더 정제 실패: {e}")
        return request_data


def rebuild_request_with_modified_body(request_data: bytes, new_body: bytes) -> bytes:
    """HTTP 요청의 body를 변경하고 Content-Length 업데이트"""
    new_length = len(new_body)
    request_data = re.sub(
        rb'Content-Length:\s*\d+',
        f'Content-Length: {new_length}'.encode(),
        request_data, flags=re.IGNORECASE
    )
    headers_end = request_data.find(b'\r\n\r\n')
    if headers_end != -1:
        request_data = request_data[:headers_end + 4] + new_body
    return request_data


def rebuild_response_with_modified_body(response_data: bytes, new_body: bytes) -> bytes:
    """HTTP 응답의 body를 변경하고 Content-Length 업데이트"""
    new_length = len(new_body)
    response_data = re.sub(
        rb'Content-Length:\s*\d+',
        f'Content-Length: {new_length}'.encode(),
        response_data, flags=re.IGNORECASE
    )
    headers_end = response_data.find(b'\r\n\r\n')
    if headers_end != -1:
        response_data = response_data[:headers_end + 4] + new_body
    return response_data
