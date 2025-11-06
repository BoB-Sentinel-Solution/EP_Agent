#!/usr/bin/env python3
"""
파일 캐시 매니저 - 업로드된 파일 임시 저장 및 매칭
"""
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from mitmproxy import ctx

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


class FileCacheManager:
    """파일 캐시 관리 및 타임아웃 처리"""

    def __init__(self, timeout_seconds: int = 10, on_timeout: Optional[Callable] = None):
        """
        Args:
            timeout_seconds: 캐시 타임아웃 시간 (초)
            on_timeout: 타임아웃 시 호출할 콜백 함수
                        시그니처: (file_id: str, cached_data: dict) -> None
        """
        self.file_cache: Dict[str, Dict[str, Any]] = {}
        self.timeout_seconds = timeout_seconds
        self.on_timeout = on_timeout

        # 타임아웃 체크 스레드
        self._thread_running = True
        self.timeout_thread = threading.Thread(target=self._check_timeout_files, daemon=True)
        self.timeout_thread.start()
        info(f"[CACHE] 파일 타임아웃 체크 스레드 시작 ({timeout_seconds}초)")

    def add_file(self, file_id: str, attachment: Dict[str, Any], parse_time: float = 0):
        """
        파일을 캐시에 추가

        Args:
            file_id: 파일 식별자
            attachment: 파일 데이터 {"format": str, "data": str}
            parse_time: 파싱 시간
        """
        self.file_cache[file_id] = {
            "attachment": attachment,
            "timestamp": datetime.now(),
            "parse_time": parse_time
        }
        info(f"[CACHE] 파일 저장: {file_id} | {attachment.get('format')} | {parse_time:.4f}초 | POST 대기중...")


    def get_cached_file(self, host: str, request_body: str = "") -> Optional[Dict[str, Any]]:
        """
        호스트에 맞는 방식으로 캐시된 파일 가져오기
        (파일 처리 기능이 제거되어 항상 None 반환)

        Args:
            host: 호스트명
            request_body: 요청 본문 (ChatGPT용)

        Returns:
            None (파일 처리 기능 제거됨)
        """
        # 파일 처리 기능이 제거되었으므로 항상 None 반환
        return None

    def _check_timeout_files(self):
        """주기적으로 캐시를 확인하여 타임아웃된 파일 처리"""
        while self._thread_running:
            time.sleep(2)  # 2초마다 체크
            current_time = datetime.now()

            for file_id, cached_data in list(self.file_cache.items()):
                timestamp = cached_data["timestamp"]
                elapsed = (current_time - timestamp).total_seconds()

                if elapsed > self.timeout_seconds:
                    info(f"[TIMEOUT] 파일 타임아웃: {file_id} ({elapsed:.1f}초 경과)")

                    # 콜백 호출
                    if self.on_timeout:
                        try:
                            self.on_timeout(file_id, cached_data)
                        except Exception as e:
                            info(f"[TIMEOUT] 콜백 오류: {e}")

                    # 캐시에서 제거
                    if file_id in self.file_cache:  # 콜백에서 이미 제거했을 수도 있음
                        del self.file_cache[file_id]
                        info(f"[TIMEOUT] 파일 제거: {file_id}")

    def stop(self):
        """타임아웃 체크 스레드 종료"""
        self._thread_running = False
        if self.timeout_thread.is_alive():
            self.timeout_thread.join(timeout=5)
