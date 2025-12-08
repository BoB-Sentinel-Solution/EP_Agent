#!/usr/bin/env python3
"""
캐시 매니저 - ChatGPT POST/PUT 매칭 및 file_id 매핑
"""
from datetime import datetime
from typing import Dict, Any, Optional
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
    """ChatGPT/Claude POST/PUT 매칭 및 file_id 매핑 관리"""

    def __init__(self):
        """캐시 매니저 초기화"""
        # ChatGPT POST 메타데이터 임시 저장 (PUT과 매칭용)
        self.file_cache: Dict[str, Dict[str, Any]] = {}

        # ChatGPT/Claude file_id 매핑 (원본 file_id → 새 file_id + size)
        self.file_id_mapping: Dict[str, Dict[str, Any]] = {}

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

    def save_file_id_mapping(self, original_file_id: str, new_file_id: str, original_size: int = None, new_size: int = None):
        """원본 file_id → 새 file_id 매핑 저장 (크기 정보 포함)

        Args:
            original_file_id: 원본 POST에서 받은 file_id
            new_file_id: 새 POST에서 받은 file_id
            original_size: 원본 파일 크기 (bytes)
            new_size: 변조된 파일 크기 (bytes)
        """
        self.file_id_mapping[original_file_id] = {
            "new_file_id": new_file_id,
            "original_size": original_size,
            "new_size": new_size
        }
        info(f"[CACHE] file_id 매핑 저장: {original_file_id} → {new_file_id} (size: {original_size} → {new_size})")

    def get_new_file_id(self, original_file_id: str) -> Optional[str]:
        """원본 file_id로 새 file_id 조회

        Args:
            original_file_id: 원본 file_id

        Returns:
            새 file_id 또는 None
        """
        mapping_data = self.file_id_mapping.get(original_file_id)
        if mapping_data:
            new_file_id = mapping_data.get("new_file_id") if isinstance(mapping_data, dict) else mapping_data
            info(f"[CACHE] file_id 매핑 조회: {original_file_id} → {new_file_id}")
            # 사용 후 삭제하지 않음 (여러 곳에서 사용할 수 있음)
        return new_file_id if mapping_data else None

    def get_file_mapping(self, original_file_id: str) -> Optional[dict]:
        """원본 file_id로 전체 매핑 정보 조회 (file_id + size)

        Args:
            original_file_id: 원본 file_id

        Returns:
            {"new_file_id": str, "original_size": int, "new_size": int} 또는 None
        """
        mapping_data = self.file_id_mapping.get(original_file_id)
        if mapping_data:
            info(f"[CACHE] 전체 매핑 조회: {original_file_id}")
            return mapping_data if isinstance(mapping_data, dict) else {"new_file_id": mapping_data}
        return None
