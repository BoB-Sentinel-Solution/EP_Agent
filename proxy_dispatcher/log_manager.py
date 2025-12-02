#!/usr/bin/env python3
"""
통합 로그 매니저 - 로컬 파일에 로그 저장
"""
import json
from pathlib import Path
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
        # self.last_user_log_file = self.log_file.parent / "last_user_log.json"
        self.vscode_last_user_log_file = self.log_file.parent / "vscode_last_user_log.json"
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
                # 필요한 필드만 저장 (eta, holding_time 제외)
            filtered_entry = {
                "time": log_entry.get("time"),
                "public_ip": log_entry.get("public_ip"),
                "private_ip": log_entry.get("private_ip"),
                "host": log_entry.get("host"),
                "PCName": log_entry.get("PCName"),
                "prompt": log_entry.get("prompt"),
                "attachment" : log_entry.get("attachment"),
                "interface": log_entry.get("interface")
            }
            
            # 새 로그 추가
            logs.append(filtered_entry)

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
    
    
        # ===== [추가] 'vscode_last_user' 저장/로드 함수 =====
    def save_vscode_last_user(self, log_entry: Dict[str, Any]):
        """VSCode Copilot의 'user' 마지막 로그를 파일에 저장"""
        try:
            log_copy = dict(log_entry)
            self.vscode_last_user_log_file.write_text(
                json.dumps(log_copy, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            info(f"[LogManager] 'vscode_last_user' 로그 파일 저장 완료 (Prompt: {log_entry.get('prompt', 'N/A')[:30]}...)")
        except Exception as e:
            info(f"[ERROR] 'vscode_last_user' 저장 실패: {e}")

    def load_vscode_last_user(self) -> Optional[Dict[str, Any]]:
        """파일에서 'vscode_last_user' 로그 로드"""
        info("[LogManager] 'vscode_last_user' 로그 파일 로드 시도...")
        try:
            if self.vscode_last_user_log_file.exists():
                content = self.vscode_last_user_log_file.read_text(encoding="utf-8")
                log_data = json.loads(content)
                info("[LogManager] 'vscode_last_user' 로그 로드 성공")
                return dict(log_data)
            else:
                info("[LogManager] 저장된 'vscode_last_user' 로그 파일 없음")
                return None
        except Exception as e:
            info(f"[ERROR] 'vscode_last_user' 로드 실패: {e}")
            return None

    def update_log_to_mcp(self, target_log: Dict[str, Any]):
        """
        기존 로그 파일에서 target_log와 일치하는 항목을 찾아 interface를 'mcp'로 수정합니다.
        """
        if not target_log or 'time' not in target_log:
            info("[LogManager] MCP 업데이트 대상 로그가 유효하지 않습니다.")
            return

        try:
            logs = []
            if self.log_file.exists():
                content = self.log_file.read_text(encoding="utf-8").strip()
                if content:
                    logs = json.loads(content)
            
            if not logs:
                info("[LogManager] MCP 업데이트할 로그 파일이 비어있습니다.")
                return

            found = False
            target_time = target_log['time']
            for i, log in enumerate(logs):
                # 타임스탬프와 프롬프트 일부를 비교하여 정확도 향상
                if log.get('time') == target_time and log.get('prompt') == target_log.get('prompt'):
                    info(f"[LogManager] 업데이트할 로그 발견 (Time: {target_time}). interface를 'mcp'로 변경합니다.")
                    logs[i]['interface'] = 'mcp'
                    found = True
                    break
            
            if not found:
                info(f"[LogManager] MCP 업데이트 대상을 찾지 못했습니다 (Time: {target_time}).")
                return

            # 파일에 다시 저장
            self.log_file.write_text(
                json.dumps(logs, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            info("[LogManager] 로그 파일 MCP 업데이트 완료.")

        except Exception as e:
            info(f"[ERROR] 로그 파일 MCP 업데이트 실패: {e}")