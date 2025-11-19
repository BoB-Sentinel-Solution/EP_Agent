#!/usr/bin/env python3
"""
Sentinel Proxy 공통 유틸리티 모듈
- Writer 안전 정리
- 데이터 중계 (양방향 터널링)
"""
import asyncio
import ssl
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def safe_close_writer(
    writer: Optional[asyncio.StreamWriter],
    connection_info: str,
    timeout: float = 2.0,
    ignore_ssl_errors: bool = False
):
    """
    StreamWriter 안전 정리

    Args:
        writer: 정리할 StreamWriter (None이면 무시)
        connection_info: 로깅용 연결 정보
        timeout: wait_closed 타임아웃 (초)
        ignore_ssl_errors: SSL 에러 무시 여부
    """
    try:
        if writer and not writer.is_closing():
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
                logger.debug(f"[UTIL] Writer 정리 완료: {connection_info}")
            except asyncio.TimeoutError:
                logger.debug(f"[UTIL] Writer 정리 타임아웃: {connection_info}")
            except ssl.SSLError as e:
                if ignore_ssl_errors:
                    logger.debug(f"[UTIL] Writer 정리 (SSL 에러 무시): {connection_info}")
                else:
                    logger.debug(f"[UTIL] Writer SSL 에러: {connection_info} - {e}")
            except Exception as e:
                logger.debug(f"[UTIL] Writer wait_closed 오류: {connection_info} - {e}")
    except Exception as e:
        logger.debug(f"[UTIL] Writer 정리 중 오류: {connection_info} - {e}")


async def relay_data(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction: str,
    buffer_size: int = 8192
):
    """
    데이터 중계 (양방향 터널링)

    Args:
        reader: 읽기 스트림
        writer: 쓰기 스트림
        direction: 방향 표시 (로깅용)
        buffer_size: 버퍼 크기
    """
    try:
        while True:
            try:
                data = await reader.read(buffer_size)
                if not data:
                    logger.debug(f"[RELAY] {direction} EOF")
                    break
                writer.write(data)
                await writer.drain()
            except asyncio.CancelledError:
                logger.debug(f"[RELAY] {direction} 취소됨")
                raise
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.debug(f"[RELAY] {direction} 연결 오류: {e}")
                break
    except Exception as e:
        logger.debug(f"[RELAY] {direction} 중계 오류: {e}")
