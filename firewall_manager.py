#!/usr/bin/env python3
"""
Windows 방화벽 관리자 - 프로그램 기반 인바운드 규칙 추가 담당
"""

import os
import sys
import logging
import subprocess
import ctypes

class FirewallManager:
    """Windows Defender 방화벽 규칙을 관리하는 클래스"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def is_admin(self) -> bool:
        """현재 스크립트가 관리자 권한으로 실행되었는지 확인"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def add_inbound_rule_for_program(self, rule_name: str, program_path: str):
        """지정된 프로그램에 대한 방화벽 인바운드 허용 규칙을 추가합니다."""
        if os.name != 'nt':
            self.logger.info("방화벽 자동 설정은 Windows에서만 지원됩니다.")
            return

        if not self.is_admin():
            self.logger.warning("방화벽 규칙을 추가하려면 관리자 권한이 필요합니다.")
            self.logger.warning("스크립트를 관리자 권한으로 다시 실행해주세요.")
            # 권한이 없으면 여기서 실행을 중단하거나, main.py에서 처리하도록 둡니다.
            return

        # 1. 규칙이 이미 존재하는지 확인
        try:
            check_cmd = [
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                f'name="{rule_name}"'
            ]
            result = subprocess.run(check_cmd, capture_output=True, text=True, check=True)
            if "규칙을 찾을 수 없습니다." not in result.stdout and rule_name in result.stdout:
                self.logger.info(f"방화벽 규칙 '{rule_name}'이(가) 이미 존재합니다.")
                return
        except (subprocess.CalledProcessError, FileNotFoundError):
            # netsh 명령어가 없거나 다른 오류 발생 시 규칙 추가를 시도
            pass

        # 2. 규칙 추가
        self.logger.info(f"방화벽 인바운드 규칙을 추가합니다: {rule_name}")
        try:
            add_cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in',
                'action=allow',
                f'program="{program_path}"',
                'enable=yes'
            ]
            result = subprocess.run(
                add_cmd,
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.logger.info(f"방화벽 규칙 '{rule_name}'을(를) 성공적으로 추가했습니다.")
        except FileNotFoundError:
            self.logger.error("'netsh' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"방화벽 규칙 추가에 실패했습니다: {e.stderr}")