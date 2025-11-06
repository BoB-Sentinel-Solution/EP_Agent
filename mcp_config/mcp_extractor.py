#!/usr/bin/env python3
"""
MCP 설정 파일 추출기
- Claude Desktop, Cursor, VS Code, ChatGPT의 MCP 설정을 추출
"""

import os
import json
import platform
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MCPConfigExtractor:
    """MCP 설정 파일을 추출하는 클래스"""

    def __init__(self):
        self.os_type = platform.system()
        self.configs = {}

    def get_appdata_path(self) -> Optional[Path]:
        """Windows APPDATA 경로 반환"""
        if self.os_type == "Windows":
            return Path(os.getenv('APPDATA', ''))
        elif self.os_type == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support"
        elif self.os_type == "Linux":
            return Path.home() / ".config"
        return None

    def extract_claude_config(self) -> Optional[Dict[str, Any]]:
        """Claude Desktop MCP 설정 추출"""
        try:
            appdata = self.get_appdata_path()
            if not appdata:
                logger.warning("APPDATA 경로를 찾을 수 없습니다.")
                return None

            # Claude Desktop 설정 파일 경로
            claude_config_path = appdata / "Claude" / "claude_desktop_config.json"

            if not claude_config_path.exists():
                logger.warning(f"Claude 설정 파일이 없습니다: {claude_config_path}")
                return None

            with open(claude_config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"✓ Claude MCP 설정 추출 성공: {claude_config_path}")
                return {
                    "service": "claude",
                    "config_path": str(claude_config_path),
                    "mcp_servers": config.get("mcpServers", {}),
                    "full_config": config
                }
        except Exception as e:
            logger.error(f"Claude 설정 추출 실패: {e}")
            return None

    # ========================================
    # [주석 처리] Cursor MCP 설정 추출
    # ========================================
    # def extract_cursor_config(self) -> Optional[Dict[str, Any]]:
    #     """Cursor MCP 설정 추출"""
    #     try:
    #         appdata = self.get_appdata_path()
    #
    #         # Cursor 가능한 경로들
    #         possible_paths = [
    #             # 주 경로: 홈 디렉토리의 .cursor 폴더
    #             Path.home() / ".cursor" / "mcp.json",
    #
    #             # 다른 가능성들
    #             Path.home() / ".cursor" / "mcp_config.json",
    #         ]
    #
    #         # appdata 기반 경로들 추가
    #         if appdata:
    #             possible_paths.extend([
    #                 appdata / "Cursor" / "mcp.json",
    #                 appdata / "Cursor" / "User" / "mcp.json",
    #                 appdata / "Cursor" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
    #             ])
    #
    #         for config_path in possible_paths:
    #             if config_path.exists():
    #                 with open(config_path, 'r', encoding='utf-8') as f:
    #                     config = json.load(f)
    #                     logger.info(f"✓ Cursor MCP 설정 추출 성공: {config_path}")
    #                     return {
    #                         "service": "cursor",
    #                         "config_path": str(config_path),
    #                         "mcp_servers": config.get("mcpServers", config),
    #                         "full_config": config
    #                     }
    #
    #         logger.warning("Cursor MCP 설정 파일을 찾을 수 없습니다.")
    #         return None
    #     except Exception as e:
    #         logger.error(f"Cursor 설정 추출 실패: {e}")
    #         return None

    def extract_vscode_config(self) -> Optional[Dict[str, Any]]:
        """VS Code MCP 설정 추출"""
        try:
            appdata = self.get_appdata_path()
            if not appdata:
                return None

            # VS Code 설정 경로들
            possible_paths = [
                appdata / "Code" / "User" / "mcp.json",  # 추가
            ]

            for config_path in possible_paths:
                if config_path.exists():
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)

                        # settings.json의 경우 MCP 관련 부분만 추출
                        if config_path.name == "settings.json":
                            mcp_config = {k: v for k, v in config.items() if 'mcp' in k.lower() or 'claude' in k.lower()}
                            if not mcp_config:
                                continue
                            config = mcp_config

                        logger.info(f"✓ VS Code MCP 설정 추출 성공: {config_path}")
                        return {
                            "service": "vscode",
                            "config_path": str(config_path),
                            "mcp_servers": config.get("mcpServers", config),
                            "full_config": config
                        }

            logger.warning("VS Code MCP 설정 파일을 찾을 수 없습니다.")
            return None
        except Exception as e:
            logger.error(f"VS Code 설정 추출 실패: {e}")
            return None



    def extract_all_configs(self) -> Dict[str, Any]:
        """모든 서비스의 MCP 설정 추출 (Claude, VSCode만)"""
        logger.info("=== MCP 설정 추출 시작 ===")

        results = {
            "claude": self.extract_claude_config(),
            # "cursor": self.extract_cursor_config(),  # 주석 처리
            "vscode": self.extract_vscode_config(),
            # "chatgpt": self.extract_chatgpt_config()  # 삭제
        }

        # None 값 제거
        self.configs = {k: v for k, v in results.items() if v is not None}

        logger.info(f"=== 총 {len(self.configs)}개 서비스의 MCP 설정 추출 완료 ===")
        return self.configs



