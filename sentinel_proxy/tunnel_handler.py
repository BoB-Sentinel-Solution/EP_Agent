#!/usr/bin/env python3
"""
HTTPS 투명 터널링 핸들러 (복호화 없음)
인터셉트 대상이 아닌 호스트에 대해 암호화된 상태로 데이터 전달
"""
import asyncio
import logging

logger = logging.getLogger(__name__)


class HTTPSTunnelHandler:
    """투명 HTTPS 터널링 (암호화된 상태로 전달)"""

    @staticmethod
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int):
        """
        HTTPS 투명 터널링

        Args:
            reader: 클라이언트 reader
            writer: 클라이언트 writer
            host: 목적지 호스트
            port: 목적지 포트
        """
        upstream_reader = None
        upstream_writer = None

        try:
            # 목적지 서버에 연결
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
            logger.debug(f"[TUNNEL] 투명 터널 시작: {host}:{port}")

            # 양방향 터널링
            await asyncio.gather(
                HTTPSTunnelHandler._relay(reader, upstream_writer, f"Client→{host}"),
                HTTPSTunnelHandler._relay(upstream_reader, writer, f"{host}→Client"),
                return_exceptions=True
            )

            logger.debug(f"[TUNNEL] 터널 종료: {host}:{port}")

        except asyncio.CancelledError:
            logger.debug(f"[TUNNEL] 터널 취소됨: {host}:{port}")
            raise  # CancelledError는 반드시 재발생
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug(f"[TUNNEL] 연결 오류 (정상): {host}:{port} - {e}")
        except Exception as e:
            logger.error(f"[TUNNEL] 터널링 실패 ({host}:{port}): {e}")
        finally:
            # 업스트림 연결만 정리 (클라이언트 writer는 handle_client에서 정리)
            await HTTPSTunnelHandler._safe_close_upstream(upstream_writer, f"{host}:{port}")

    @staticmethod
    async def _safe_close_upstream(upstream_writer, connection_info):
        """업스트림 Writer 안전 정리"""
        try:
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                try:
                    await asyncio.wait_for(upstream_writer.wait_closed(), timeout=2.0)
                    logger.debug(f"[TUNNEL] 업스트림 정리 완료: {connection_info}")
                except asyncio.TimeoutError:
                    logger.debug(f"[TUNNEL] 업스트림 정리 타임아웃: {connection_info}")
                except Exception as e:
                    logger.debug(f"[TUNNEL] 업스트림 wait_closed 오류: {connection_info} - {e}")
        except Exception as e:
            logger.debug(f"[TUNNEL] 업스트림 정리 중 오류: {connection_info} - {e}")

    @staticmethod
    async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """
        데이터 중계 (양방향)

        Args:
            reader: 읽기 스트림
            writer: 쓰기 스트림
            direction: 방향 표시 (로깅용)
        """
        try:
            while True:
                try:
                    data = await reader.read(8192)
                    if not data:
                        logger.debug(f"[TUNNEL] {direction} EOF")
                        break
                    writer.write(data)
                    await writer.drain()
                except asyncio.CancelledError:
                    logger.debug(f"[TUNNEL] {direction} 중계 취소됨")
                    raise  # CancelledError는 반드시 재발생
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.debug(f"[TUNNEL] {direction} 연결 오류: {e}")
                    break
        except Exception as e:
            logger.debug(f"[TUNNEL] {direction} 중계 오류: {e}")
