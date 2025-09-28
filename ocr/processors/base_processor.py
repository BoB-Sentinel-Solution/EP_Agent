#!/usr/bin/env python3
"""
LLM 파일 처리 프로세서의 기본 인터페이스

모든 LLM별 파일 처리 프로세서가 구현해야 할 공통 인터페이스를 정의합니다.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from mitmproxy import http
from pathlib import Path

class BaseLLMProcessor(ABC):
    """모든 LLM 파일 처리 프로세서의 기본 클래스"""

    def __init__(self):
        self.temp_dir = Path.home() / ".llm_proxy" / "ocr_temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.setup_processor()

    @abstractmethod
    def setup_processor(self):
        """프로세서별 초기화 로직 (OCR 엔진, 키워드 매니저 등)"""
        pass

    @abstractmethod
    def get_supported_hosts(self) -> List[str]:
        """이 프로세서가 처리할 수 있는 호스트 목록 반환"""
        pass

    @abstractmethod
    def is_file_upload_request(self, flow: http.HTTPFlow) -> bool:
        """해당 요청이 파일 업로드 요청인지 확인"""
        pass

    # 사전 차단 방식에서는 extract_file_url과 process_file_upload이 불필요함
    # 대신 process_upload_request_precheck를 구현해야 함 (선택적)

    def can_handle(self, host: str) -> bool:
        """해당 호스트를 처리할 수 있는지 확인"""
        return any(supported_host in host for supported_host in self.get_supported_hosts())

    # 파일 형식 검사는 공통 FileUtils에서 처리함 (중복 제거)

    def cleanup_temp_files(self, max_age_hours: int = 24):
        """오래된 임시 파일들을 정리 (공통 구현)"""
        try:
            import time
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600

            for temp_file in self.temp_dir.glob("*"):
                if temp_file.is_file():
                    file_age = current_time - temp_file.stat().st_mtime
                    if file_age > max_age_seconds:
                        temp_file.unlink()
                        print(f"[DEBUG] 오래된 임시 파일 삭제: {temp_file}")

        except Exception as e:
            print(f"[WARN] 임시 파일 정리 중 오류: {e}")

    @property
    @abstractmethod
    def name(self) -> str:
        """프로세서 이름"""
        pass