#!/usr/bin/env python3
"""
HTTPS 투명 터널링 핸들러 (복호화 없음)
"""
import asyncio
import logging
from sentinel_proxy.utils import safe_close_writer, relay_data, open_upstream_connection

logger = logging.getLogger(__name__)


class HTTPSTunnelHandler:
    """투명 HTTPS 터널링 (암호화된 상태로 전달)"""

    @staticmethod
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int):
        """HTTPS 투명 터널링"""
        upstream_writer = None

        try:
            # 목적지 서버에 연결
            upstream_reader, upstream_writer = await open_upstream_connection(host, port)
            if not upstream_reader:
                return

            logger.debug(f"[TUNNEL] 투명 터널 시작: {host}:{port}")

            # 양방향 터널링
            await asyncio.gather(
                relay_data(reader, upstream_writer, f"Client→{host}"),
                relay_data(upstream_reader, writer, f"{host}→Client"),
                return_exceptions=True
            )

            logger.debug(f"[TUNNEL] 터널 종료: {host}:{port}")

        except asyncio.CancelledError:
            logger.debug(f"[TUNNEL] 터널 취소됨: {host}:{port}")
            raise
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug(f"[TUNNEL] 연결 오류: {host}:{port} - {e}")
        except Exception as e:
            logger.error(f"[TUNNEL] 터널링 실패: {host}:{port} - {e}")
        finally:
            await safe_close_writer(upstream_writer, f"{host}:{port}")
