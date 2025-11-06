#!/usr/bin/env python3
"""
통합 로그 매니저 - 로컬 파일에 로그 저장
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional # <--- Optional 추가
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

        # ===== [추가] user 로그 임시 저장 파일 경로 =====
        self.last_user_log_file = self.log_file.parent / "last_user_log.json"
        # =======================================================


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

    # ===== [추가] 'last_user' 저장 함수 =====
    def save_last_user(self, log_entry: Dict[str, Any]):
        """'user' role의 마지막 로그를 파일에 저장"""
        try:
            # [중요] dict()로 복사본을 저장하여 원본 log_entry가 수정되는 것을 방지
            log_copy = dict(log_entry)
            self.last_user_log_file.write_text(
                json.dumps(log_copy, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            info(f"[LogManager] 'last_user' 로그 파일 저장 완료 (Prompt: {log_entry.get('prompt', 'N/A')[:30]}...)")
        except Exception as e:
            info(f"[ERROR] 'last_user' 저장 실패: {e}")
    # ==========================================

    # ===== [추가] 'last_user' 로드 함수 =====
    def load_last_user(self) -> Optional[Dict[str, Any]]:
        """파일에서 'last_user' 로그 로드"""
        info("[LogManager] 'last_user' 로그 파일 로드 시도...")
        try:
            if self.last_user_log_file.exists():
                content = self.last_user_log_file.read_text(encoding="utf-8")
                log_data = json.loads(content)
                info("[LogManager] 'last_user' 로그 로드 성공")
                # [중요] 복사본을 반환하여 원본 파일 데이터가 수정되는 것을 방지
                return dict(log_data)
            else:
                info("[LogManager] 저장된 'last_user' 로그 파일 없음")
                return None
        except Exception as e:
            info(f"[ERROR] 'last_user' 로드 실패: {e}")
            return None
    # ==========================================