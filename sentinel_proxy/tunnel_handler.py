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

        except (asyncio.CancelledError, GeneratorExit):
            logger.debug(f"[TUNNEL] 터널 취소됨: {host}:{port}")
            raise  # CancelledError/GeneratorExit는 반드시 재발생시켜야 함
        except RuntimeError as e:
            if "GeneratorExit" in str(e):
                # GeneratorExit가 RuntimeError로 감싸진 경우 - 조용히 무시
                logger.debug(f"[TUNNEL] 터널 종료됨: {host}:{port}")
            else:
                logger.error(f"[TUNNEL] Runtime 오류 ({host}:{port}): {e}")
        except Exception as e:
            logger.error(f"[TUNNEL] 터널링 실패 ({host}:{port}): {e}")
        finally:
            # 업스트림 연결만 정리 (클라이언트 writer는 handle_client에서 정리)
            try:
                if upstream_writer and not upstream_writer.is_closing():
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # 원격 호스트가 이미 연결을 끊은 경우 무시
                pass
            except Exception as e:
                logger.debug(f"[TUNNEL] 업스트림 Writer 정리 중 오류: {e}")

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
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            # 정상 취소
            pass
        except Exception as e:
            logger.debug(f"[TUNNEL] {direction} 중계 종료: {e}")
