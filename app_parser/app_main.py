#!/usr/bin/env python3
"""
통합 LLM 트래픽 로거 - 메인 애플리케이션 (의존성 주입 버전)
- 순환 참조 문제를 해결하기 위해 어댑터에 로그 기능을 직접 주입합니다.
"""
import json
import re
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Dict, Any, Optional, Set

from app_parser.adapter.cursor import CursorAdapter
from app_parser.adapter.windsurf import WindsurfAdapter


# -------------------------------
# 유틸리티 클래스 
# -------------------------------
class FileUtils:
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types

    @staticmethod
    def safe_filename(original_name: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:50]
        return f"{timestamp}_{safe_stem}{ext}"

# -------------------------------
# 메인 통합 로거
# -------------------------------
class UnifiedAppLogger:
    def __init__(self):
        """디렉터리를 초기화하고, 감시할 호스트 목록과 어댑터를 설정합니다."""
        self.base_dir = Path.home() / ".llm_proxy"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # App/MCP 호스트 키워드 (부분 매칭)
        self.API_HOST_KEYWORDS: Set[str] = {
            "cursor.sh", "localhost", "127.0.0.1",
            "server.self-serve.windsurf.com"
        }
        
        # 어댑터 생성 (프롬프트 추출만 수행)
        self.adapters: Dict[str, Any] = {
            ".cursor.sh": CursorAdapter(),
            "server.self-serve.windsurf.com": WindsurfAdapter(),
        }
        
        print("\n[INFO] App/MCP 핸들러가 시작되었습니다.")
        print(f"[INFO] 감시 호스트 키워드: {', '.join(sorted(self.API_HOST_KEYWORDS))}")
        print(f"[INFO] 로드된 어댑터: {', '.join(self.adapters.keys())}\n")

    def _get_adapter(self, host: str) -> Optional[Any]:
        """주어진 호스트에 맞는 어댑터를 찾습니다."""
        for host_keyword, adapter in self.adapters.items():
            if host_keyword in host:
                return adapter
        return None

    def extract_prompt_only(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트만 추출하여 반환 (로깅/서버 전송 없음)
        반환: {"prompt": str, "interface": str} 또는 None
        """
        host = flow.request.pretty_host

        # 디버그: 호스트 체크 로깅
        print(f"[APP_MAIN] 요청 호스트: {host}")

        # 부분 매칭으로 호스트 확인
        if not any(keyword in host for keyword in self.API_HOST_KEYWORDS):
            print(f"[APP_MAIN] 호스트가 API_HOST_KEYWORDS에 매칭되지 않음: {host}")
            return None

        print(f"[APP_MAIN] API_HOST_KEYWORDS 매칭 성공: {host}")
        adapter = self._get_adapter(host)

        if not adapter:
            print(f"[APP_MAIN] 어댑터를 찾지 못함: {host}")
            return None

        print(f"[APP_MAIN] 어댑터 찾음, 프롬프트 추출 시도")

        # 어댑터로부터 프롬프트 추출
        result = adapter.extract_prompt(flow)

        if result:
            print(f"[APP_MAIN] 프롬프트 추출 성공: {result.get('prompt', '')[:50]}")
        else:
            print(f"[APP_MAIN] 프롬프트 추출 실패")

        return result

#addons = [UnifiedAppLogger()]