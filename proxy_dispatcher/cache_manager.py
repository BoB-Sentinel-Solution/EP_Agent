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

    def add_file(self, file_id: str, attachment: Dict[str, Any], flow=None, parse_time: float = 0):
        """
        파일을 캐시에 추가

        Args:
            file_id: 파일 식별자
            attachment: 파일 데이터 {"format": str, "data": str}
            flow: mitmproxy HTTPFlow 객체 (파일 변조를 위해 홀딩)
            parse_time: 파싱 시간
        """
        self.file_cache[file_id] = {
            "attachment": attachment,
            "flow": flow,  # flow 객체 저장 (PUT 요청 홀딩용)
            "timestamp": datetime.now(),
            "parse_time": parse_time
        }
        info(f"[CACHE] 파일 저장: {file_id} | {attachment.get('format')} | {parse_time:.4f}초 | POST 대기중...")

    def match_file_for_claude(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Claude용 파일 매칭 (FIFO - 타임스탬프 순서)

        Args:
            host: 호스트명

        Returns:
            attachment 딕셔너리 또는 None
        """
        if "claude.ai" not in host:
            return None

        # claude:로 시작하는 캐시 항목 찾기
        claude_files = [(fid, data) for fid, data in self.file_cache.items() if fid.startswith("claude:")]
        if not claude_files:
            return None

        # 타임스탬프 순서로 정렬 (가장 오래된 것)
        claude_files.sort(key=lambda x: int(x[0].split(':')[1]))
        file_id, cached_data = claude_files[0]

        attachment = cached_data["attachment"]
        info(f"[CACHE Claude] 파일 매칭 (FIFO): {file_id} | {attachment.get('format')}")

        # 캐시에서 제거
        del self.file_cache[file_id]
        return attachment

    def match_file_for_chatgpt(self, request_body: str) -> Optional[Dict[str, Any]]:
        """
        ChatGPT용 파일 매칭 (File ID 기반)

        Args:
            request_body: 요청 본문 (문자열)

        Returns:
            attachment 딕셔너리 또는 None
        """
        for file_id, cached_data in list(self.file_cache.items()):
            # File ID 정규화 (하이픈 제거하여 비교)
            normalized_file_id = file_id.replace('-', '')
            if normalized_file_id in request_body or file_id in request_body:
                attachment = cached_data["attachment"]
                info(f"[CACHE ChatGPT] 파일 매칭: {file_id} | {attachment.get('format')}")

                # 캐시에서 제거
                del self.file_cache[file_id]
                return attachment

        return None

    def get_cached_file(self, host: str, request_body: str = "") -> Optional[Dict[str, Any]]:
        """
        호스트에 맞는 방식으로 캐시된 파일 가져오기

        Args:
            host: 호스트명
            request_body: 요청 본문 (ChatGPT용)

        Returns:
            attachment 딕셔너리 또는 None
        """
        if "claude.ai" in host:
            return self.match_file_for_claude(host)
        else:
            return self.match_file_for_chatgpt(request_body)

    def get_cached_file_with_flow(self, host: str, request_body: str = "") -> Optional[tuple]:
        """
        호스트에 맞는 방식으로 캐시된 파일 + flow + decision 가져오기

        Args:
            host: 호스트명
            request_body: 요청 본문 (ChatGPT용)

        Returns:
            (file_id, attachment, flow, file_decision, parse_time) 튜플 또는 None
        """
        # 먼저 file_id 찾기
        file_id = None

        if "claude.ai" in host:
            claude_files = [(fid, data) for fid, data in self.file_cache.items() if fid.startswith("claude:")]
            if claude_files:
                claude_files.sort(key=lambda x: int(x[0].split(':')[1]))
                file_id = claude_files[0][0]
        else:
            for fid in list(self.file_cache.keys()):
                normalized_file_id = fid.replace('-', '')
                if normalized_file_id in request_body or fid in request_body:
                    file_id = fid
                    break

        if not file_id or file_id not in self.file_cache:
            return None

        cached_data = self.file_cache[file_id]
        attachment = cached_data["attachment"]
        flow_data = cached_data.get("flow")  # dict: {"flow": flow, "decision": decision}
        parse_time = cached_data.get("parse_time", 0)

        # flow_data가 dict인 경우 (새 방식)
        if isinstance(flow_data, dict):
            cached_flow = flow_data.get("flow")
            file_decision = flow_data.get("decision", {})
        else:
            # 이전 방식 호환
            cached_flow = flow_data
            file_decision = {}

        info(f"[CACHE] 파일 + flow + decision 매칭: {file_id} | {attachment.get('format')}")

        # 캐시에서 제거
        del self.file_cache[file_id]

        return (file_id, attachment, cached_flow, file_decision, parse_time)

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


    def add_chatgpt_post_metadata(self, flow, metadata):
        """ChatGPT POST 메타데이터 저장 (통과시키고 나중에 사용)

        Args:
            flow: mitmproxy HTTPFlow 객체 (전체 저장)
            metadata: 파일 메타데이터 {"file_name": str, "file_size": int, ...}

        Returns:
            temp_id: 임시 파일 ID
        """
        import time
        temp_id = f"chatgpt_post_{int(time.time() * 1000)}"

        self.file_cache[temp_id] = {
            "type": "chatgpt_post",
            "flow": flow,  # 전체 flow 저장 (나중에 복사해서 사용)
            "metadata": metadata,
            "timestamp": datetime.now()
        }

        info(f"[CACHE ChatGPT] POST 메타데이터 저장: {metadata.get('file_name')} | {metadata.get('file_size')} bytes")
        return temp_id

    def get_recent_chatgpt_post(self):
        """최근 ChatGPT POST 메타데이터 가져오기 (5초 이내)

        Returns:
            dict: {"flow": flow, "metadata": dict, "temp_id": str} 또는 None
        """
        current_time = datetime.now()

        # chatgpt_post로 시작하는 캐시 찾기
        candidates = []
        for temp_id, data in list(self.file_cache.items()):
            if not temp_id.startswith("chatgpt_post_"):
                continue
            if data.get("type") != "chatgpt_post":
                continue

            elapsed = (current_time - data["timestamp"]).total_seconds()
            if elapsed < 5.0:
                candidates.append((temp_id, elapsed, data))

        if candidates:
            # 가장 최근 것 선택
            candidates.sort(key=lambda x: x[1])
            temp_id, _, data = candidates[0]

            info(f"[CACHE ChatGPT] POST 메타데이터 매칭: {temp_id}")

            # 삭제하지 말고 그대로 유지 (response에서 사용)
            return {
                "flow": data["flow"],
                "metadata": data["metadata"],
                "temp_id": temp_id
            }

        return None

    def save_chatgpt_upload_url(self, temp_id: str, upload_url: str):
        """ChatGPT POST에 대한 새로운 upload_url 저장

        Args:
            temp_id: POST의 temp_id
            upload_url: 새로운 upload_url
        """
        if temp_id in self.file_cache:
            self.file_cache[temp_id]["upload_url"] = upload_url
            info(f"[CACHE ChatGPT] upload_url 저장: {temp_id} → {upload_url[:100]}...")
        else:
            info(f"[CACHE ChatGPT] temp_id 없음: {temp_id}")

    def get_chatgpt_upload_url(self, original_url: str) -> Optional[str]:
        """원본 upload_url에 해당하는 새 upload_url 찾기

        Args:
            original_url: 원본 POST 응답의 upload_url

        Returns:
            새 upload_url 또는 None
        """
        # 최근 POST 중에서 upload_url이 있는 것 찾기
        for temp_id, data in list(self.file_cache.items()):
            if not temp_id.startswith("chatgpt_post_"):
                continue

            new_upload_url = data.get("upload_url")
            if new_upload_url:
                info(f"[CACHE ChatGPT] 새 upload_url 찾음: {temp_id}")
                # 사용 후 캐시 삭제
                del self.file_cache[temp_id]
                return new_upload_url

        return None

    def stop(self):
        """타임아웃 체크 스레드 종료"""
        self._thread_running = False
        if self.timeout_thread.is_alive():
            self.timeout_thread.join(timeout=5)
