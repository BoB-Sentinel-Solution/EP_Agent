#!/usr/bin/env python3
"""
시스템 프록시 관리자 - Windows 시스템 프록시 설정/복원
"""

import os
import logging
from typing import Optional, Dict


class SystemProxyManager:
    """Windows 시스템 프록시 설정 관리"""

    def __init__(self):
        self.original_proxy_settings: Optional[Dict] = None
        self.logger = logging.getLogger(__name__)

    def backup_original_proxy(self):
        """시스템 프록시 설정을 백업"""
        if os.name != 'nt' or self.original_proxy_settings is not None:
            return

        try:
            import winreg
            INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ)

            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                server, enabled = "", 0

            self.original_proxy_settings = {"ProxyServer": server, "ProxyEnable": enabled}
            self.logger.info(f"기존 프록시 설정 백업: {self.original_proxy_settings}")
            winreg.CloseKey(key)
        except Exception as e:
            self.logger.error(f"기존 프록시 설정 백업 실패: {e}")

    def set_system_proxy(self, enable: bool, port: int = None):
        """Windows 시스템 프록시 설정 또는 복원"""
        if os.name != 'nt':
            return

        try:
            import winreg
            import ctypes

            INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_WRITE)

            if enable:
                if port is None:
                    raise ValueError("프록시 활성화 시 포트 번호가 필요합니다.")

                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
                # localhost/127.0.0.1 우회 설정 (MCP 서버 등)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.0.0.1;*.local;<local>")
                self.logger.info(f"시스템 프록시 설정 -> 127.0.0.1:{port}")
            else:
                # 원래 설정으로 복원
                settings = self.original_proxy_settings
                if settings:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, settings["ProxyEnable"])
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, settings["ProxyServer"])
                    self.logger.info("시스템 프록시를 원래 설정으로 복원합니다.")
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
                    self.logger.info("백업된 설정이 없어 시스템 프록시를 비활성화합니다.")

            winreg.CloseKey(key)

            # IE 설정 새로고침
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception as e:
            self.logger.error(f"시스템 프록시 설정/복원 실패: {e}")
