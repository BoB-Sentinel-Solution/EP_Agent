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

# 필요한 어댑터를 가져옵니다.
from adapter.cursor import CursorAdapter

# BaseAdapter 클래스는 이제 필요 없으므로 삭제합니다.

# -------------------------------
# 유틸리티 클래스 (변경 없음)
# -------------------------------
class FileUtils:
    # ... 내용은 이전과 동일 ...
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
class UnifiedLLMLogger:
    def __init__(self):
        """디렉터리를 초기화하고, 감시할 호스트 목록과 어댑터를 설정합니다."""
        self.base_dir = Path.home() / ".llm_proxy"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.API_HOSTS: Set[str] = {
            "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com", "api.groq.com", "api.cohere.ai", "api.deepseek.com",
            "api2.cursor.sh", "api3.cursor.sh", "repo42.cursor.sh", "localhost", "127.0.0.1",
            "metrics.cursor.sh"
        }
        
        # [핵심] 어댑터를 생성할 때, 로그 저장 함수와 파일명을 직접 전달(주입)합니다.
        self.adapters: Dict[str, Any] = {
            ".cursor.sh": CursorAdapter(
                save_log_func=self._save_log_to_file,
                log_filename="cursor_requests.json"
            ),
        }
        
        print("\n[INFO] 통합 모듈화 로거가 시작되었습니다 (의존성 주입 모델).")
        print(f"[INFO] 로그 저장 기본 폴더: {self.base_dir}")
        print(f"[INFO] 로드된 특수 어댑터: {', '.join(self.adapters.keys())}\n")

    def _save_log_to_file(self, entry: Dict[str, Any], filename: str):
        """모든 어댑터가 공용으로 사용할 로그 저장 기능"""
        log_file_path = self.base_dir / filename
        try:
            logs = []
            if log_file_path.exists():
                try:
                    content = log_file_path.read_text(encoding='utf-8').strip()
                    if content: logs = json.loads(content)
                    if not isinstance(logs, list): logs = []
                except (json.JSONDecodeError, FileNotFoundError):
                    logs = []
            
            logs.append(entry)
            logs = logs[-200:]
            
            log_file_path.write_text(
                json.dumps(logs, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )
        except Exception as e:
            print(f"\n[CRITICAL] 로그 저장 실패 ({filename}): {e}\n")

    def _get_adapter(self, host: str) -> Optional[Any]:
        """주어진 호스트에 맞는 어댑터를 찾습니다."""
        for host_keyword, adapter in self.adapters.items():
            if host_keyword in host:
                return adapter
        return None

    def request(self, flow: http.HTTPFlow):
        """나가는 요청을 올바른 어댑터에 전달합니다."""
        host = flow.request.pretty_host
        
        if host not in self.API_HOSTS:
            return

        adapter = self._get_adapter(host)
        
        if adapter:
            # 어댑터에게 요청 처리를 위임합니다. 이제 로깅은 어댑터가 알아서 합니다.
            adapter.process_request(flow)

addons = [UnifiedLLMLogger()]