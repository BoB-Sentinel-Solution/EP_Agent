#!/usr/bin/env python3
"""
통합 로그 매니저 - 로컬 파일에 로그 저장
"""
import json
from pathlib import Path
from typing import Dict, Any
from mitmproxy import ctx

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


class LogManager:
    """통합 로그 파일 관리"""

    def __init__(self, log_file_path: Path, max_entries: int = 100):
        """
        Args:
            log_file_path: 로그 파일 경로
            max_entries: 최대 로그 항목 개수
        """
        self.log_file = log_file_path
        self.max_entries = max_entries
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def save_log(self, log_entry: Dict[str, Any]):
        """
        통합 로그 파일에 저장

        Args:
            log_entry: 저장할 로그 엔트리
        """
        try:
            logs = []

            # 기존 로그 읽기
            if self.log_file.exists():
                try:
                    content = self.log_file.read_text(encoding="utf-8").strip()
                    if content:
                        logs = json.loads(content)
                except (json.JSONDecodeError, OSError):
                    logs = []

            # 새 로그 추가
            logs.append(log_entry)

            # 최대 개수 유지
            if len(logs) > self.max_entries:
                logs = logs[-self.max_entries:]

            # 파일에 저장
            self.log_file.write_text(
                json.dumps(logs, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

        except Exception as e:
            info(f"[ERROR] 통합 로그 저장 실패: {e}")
