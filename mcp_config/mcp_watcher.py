#!/usr/bin/env python3
"""
MCP 설정 파일 변경 감지 및 자동 전송
- watchdog를 사용하여 MCP 설정 파일 변경 감지
- 변경 감지 시 자동으로 설정 추출 및 서버 전송
"""

import os
import time
import logging
from pathlib import Path
from typing import List, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from mcp_config.mcp_extractor import MCPConfigExtractor
# from mcp_config.mcp_sender import MCPConfigSender  # [디버깅 모드] 서버 전송 비활성화
from mcp_config.mcp_debugger import print_mcp_json

logger = logging.getLogger(__name__)


class MCPConfigChangeHandler(FileSystemEventHandler):
    """MCP 설정 파일 변경 이벤트 핸들러 - 디버깅 모드"""

    def __init__(self, debounce_seconds: float = 2.0):
        """
        Args:
            debounce_seconds: 중복 이벤트 무시 시간 (초)
        """
        super().__init__()
        self.extractor = MCPConfigExtractor()
        self.debounce_seconds = debounce_seconds
        self.last_modified = {}  # 파일별 마지막 처리 시간

    def on_modified(self, event):
        """파일 변경 이벤트 처리"""
        if event.is_directory:
            return

        file_path = event.src_path

        # MCP 관련 파일명만 처리 (필터링)
        if not self._is_mcp_config_file(file_path):
            return

        current_time = time.time()

        # Debounce: 같은 파일이 짧은 시간 내에 여러 번 수정되는 경우 무시
        if file_path in self.last_modified:
            if current_time - self.last_modified[file_path] < self.debounce_seconds:
                return

        self.last_modified[file_path] = current_time

        logger.info(f"MCP 설정 파일 변경 감지: {file_path}")

        # 어떤 서비스의 설정인지 판단
        service = self._identify_service(file_path)
        if not service:
            logger.warning(f"알 수 없는 MCP 설정 파일: {file_path}")
            return

        logger.info(f"{service.upper()} 파일 읽기 중...")

        # 파일 내용을 그대로 읽기 (JSON 파싱 시도 안 함)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_content = f.read()

            logger.info(f"✓ {service.upper()} 파일 읽기 완료 ({len(raw_content)} bytes)")

            # [디버깅 모드] 파일 내용 그대로 출력
            logger.info(f"디버깅 출력 중...")
            print_mcp_json(service, file_path, raw_content, status="activate")

        except Exception as e:
            logger.error(f"✗ {service.upper()} 파일 읽기 실패: {e}")

    def on_deleted(self, event):
        """파일 삭제 이벤트 처리"""
        if event.is_directory:
            return

        file_path = event.src_path

        # MCP 관련 파일명만 처리 (필터링)
        if not self._is_mcp_config_file(file_path):
            return

        logger.info(f"MCP 설정 파일 삭제 감지: {file_path}")

        # 어떤 서비스의 설정인지 판단
        service = self._identify_service(file_path)
        if not service:
            logger.warning(f"알 수 없는 MCP 설정 파일: {file_path}")
            return

        logger.info(f"{service.upper()} 삭제 정보 출력 중...")

        # 삭제된 파일은 내용이 없으므로 빈 문자열 또는 삭제 메시지
        print_mcp_json(service, file_path, "[FILE DELETED]", status="delete")

        # debounce 목록에서 제거
        if file_path in self.last_modified:
            del self.last_modified[file_path]

    def _is_mcp_config_file(self, file_path: str) -> bool:
        """MCP 설정 파일인지 확인 (필터링)"""
        file_name = os.path.basename(file_path).lower()

        # MCP 관련 파일명만 허용
        mcp_file_patterns = [
            "claude_desktop_config.json",  # Claude
            "mcp.json",                     # Cursor
            "mcp_config.json",              # 일반 MCP 설정
            "cline_mcp_settings.json",      # Cline 확장
            "mcp_settings.json",            # MCP 설정
        ]

        return any(pattern in file_name for pattern in mcp_file_patterns)

    def _identify_service(self, file_path: str) -> str:
        """파일 경로로 서비스 식별"""
        file_path_lower = file_path.lower()
        file_name = os.path.basename(file_path_lower)

        # 파일명으로 먼저 판단
        if "claude_desktop_config.json" in file_name:
            return "claude"
        elif "mcp.json" in file_name and ".cursor" in file_path_lower:
            return "cursor"
        elif "cursor" in file_path_lower and ("mcp" in file_name or "cline" in file_name):
            return "cursor"
        elif "code" in file_path_lower and "cursor" not in file_path_lower and ("mcp" in file_name or "cline" in file_name):
            return "vscode"
        elif ("chatgpt" in file_path_lower or "openai" in file_path_lower) and "mcp" in file_name:
            return "chatgpt"

        return None

    def _extract_service_config(self, service: str):
        """특정 서비스의 MCP 설정 추출 (Claude, VSCode만)"""
        if service == "claude":
            return self.extractor.extract_claude_config()
        # elif service == "cursor":  # 주석 처리
        #     return self.extractor.extract_cursor_config()
        elif service == "vscode":
            return self.extractor.extract_vscode_config()
        # elif service == "chatgpt":  # 삭제
        #     return self.extractor.extract_chatgpt_config()
        return None


class MCPConfigWatcher:
    """MCP 설정 파일 감시자 - 디버깅 모드"""

    def __init__(self):
        """디버깅 모드로 초기화 (서버 전송 없음)"""
        self.event_handler = MCPConfigChangeHandler()
        self.observer = Observer()
        self.watched_paths: Set[Path] = set()

    def _get_watch_paths(self) -> List[Path]:
        """감시할 MCP 설정 파일 경로 목록 반환"""
        extractor = MCPConfigExtractor()
        appdata = extractor.get_appdata_path()
        if not appdata:
            logger.error("APPDATA 경로를 찾을 수 없습니다.")
            return []

        watch_paths = []

        # Claude Desktop
        claude_config = appdata / "Claude" / "claude_desktop_config.json"
        if claude_config.exists():
            watch_paths.append(claude_config.parent)

        # Cursor (여러 가능한 경로)
        # cursor_paths = [
        #     Path.home() / ".cursor",  # 주 경로
        #     appdata / "Cursor" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings",
        #     appdata / "Cursor" / "User",
        #     appdata / "Cursor",
        # ]
        # for path in cursor_paths:
        #     if path.exists():
        #         watch_paths.append(path)

        # VS Code
        vscode_paths = [
            appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings",
            appdata / "Code" / "User",
        ]
        for path in vscode_paths:
            if path.exists():
                watch_paths.append(path)

        return watch_paths

    def start(self):
        """파일 감시 시작"""
        watch_paths = self._get_watch_paths()

        if not watch_paths:
            logger.warning("감시할 MCP 설정 파일 경로가 없습니다.")
            return False

        logger.info("=== MCP 설정 파일 감시 시작 ===")

        for path in watch_paths:
            if path in self.watched_paths:
                continue

            try:
                self.observer.schedule(self.event_handler, str(path), recursive=True)
                self.watched_paths.add(path)
                logger.info(f"감시 중: {path}")
            except Exception as e:
                logger.error(f"경로 감시 실패 ({path}): {e}")

        if not self.watched_paths:
            logger.error("모든 경로 감시 설정 실패")
            return False

        # 먼저 초기 설정 출력 (observer 시작 전)
        self._send_initial_configs()

        # 그 다음 observer 시작 (중복 출력 방지)
        self.observer.start()
        logger.info(f"✓ {len(self.watched_paths)}개 경로 감시 시작됨")

        return True

    def _send_initial_configs(self):
        """초기 MCP 설정 디버깅 출력 (raw 파일 읽기 - JSON 파싱 없음)"""
        logger.info("=== 초기 MCP 설정 디버깅 출력 ===")

        # JSON 파싱 없이 파일 경로만 찾기
        extractor = MCPConfigExtractor()
        appdata = extractor.get_appdata_path()

        if not appdata:
            logger.warning("APPDATA 경로를 찾을 수 없습니다.")
            return

        # 각 서비스별 파일 경로 찾기
        config_files = []

        # Claude
        claude_path = appdata / "Claude" / "claude_desktop_config.json"
        if claude_path.exists():
            config_files.append(("claude", str(claude_path)))

        # VS Code
        vscode_paths = [
            appdata / "Code" / "User" / "mcp.json",
            appdata / "Code" / "User" / "mcp_config.json",
            appdata / "Code" / "User" / "mcp_settings.json",
        ]
        for path in vscode_paths:
            if path.exists():
                config_files.append(("vscode", str(path)))
                break

        if not config_files:
            logger.warning("추출된 MCP 설정 파일이 없습니다.")
            return

        # 파일 내용 읽기 및 출력
        for service, config_path in config_files:
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    raw_content = f.read()

                logger.info(f"{service.upper()} 초기 설정 출력 중... ({len(raw_content)} bytes)")
                print_mcp_json(service, config_path, raw_content, status="activate")

                # 중복 출력 방지
                self.event_handler.last_modified[config_path] = time.time()

            except Exception as e:
                logger.error(f"{service.upper()} 파일 읽기 실패: {e}")

    def stop(self):
        """파일 감시 중지"""
        logger.info("MCP 설정 파일 감시 중지 중...")
        self.observer.stop()
        self.observer.join()
        logger.info("MCP 설정 파일 감시가 중지되었습니다.")

    def is_running(self) -> bool:
        """감시자 실행 상태 확인"""
        return self.observer.is_alive()
