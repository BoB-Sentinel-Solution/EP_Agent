#!/usr/bin/env python3
"""
프록시 관리자 - mitmproxy 실행 및 시스템 프록시 설정 담당
"""

import os
import sys
import time
import socket
import logging
import subprocess
import re  # re 모듈 import 추가
from pathlib import Path
from typing import Optional, Dict


class ProxyManager:
    """프록시 서버 실행 및 시스템 프록시 설정을 담당하는 클래스"""

    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.mitm_dir = app_dir / ".mitmproxy"
        self.port: int = 8081
        self.process: Optional[subprocess.Popen] = None
        self.is_running: bool = False
        self.original_proxy_settings: Optional[Dict] = None
        self.logger = logging.getLogger(__name__)

    def find_mitmdump_executable(self) -> Optional[str]:
            """실행 가능한 mitmdump.exe의 전체 경로를 찾아서 반환합니다."""
            scripts_dir = Path(sys.executable).parent / "Scripts"
            
            # 1. Python Scripts 폴더에서 직접 찾기 (가상환경 등)
            mitmdump_path = scripts_dir / "mitmdump.exe"
            if mitmdump_path.exists():
                return str(mitmdump_path)
                
            # 2. 시스템 PATH 환경 변수에서 찾기
            try:
                result = subprocess.run(
                    ['where', 'mitmdump.exe'],
                    capture_output=True, text=True, check=True
                )
                # where 명령어는 여러 경로를 반환할 수 있으므로 첫 번째 것을 사용
                return result.stdout.strip().split('\n')[0]
            except (subprocess.CalledProcessError, FileNotFoundError):
                return None

    def backup_original_proxy(self):
        """시스템 프록시 설정을 시작 전에 미리 백업"""
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
    
    def start_proxy(self, script_file: Path) -> bool:
        """mitmdump를 백그라운드 프로세스로 실행 (다양한 실행 방법 시도)"""
        if self.is_running:
            self.logger.warning("프록시가 이미 실행 중입니다.")
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

        # upstream_proxy = None
        # if self.original_proxy_settings and self.original_proxy_settings.get("ProxyEnable") == 1:
        #     server_str = self.original_proxy_settings.get("ProxyServer", "")
        #     match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)', server_str)
        #     if match:
        #         upstream_proxy = f"http://{match.group(1)}"
        #         self.logger.info(f"기존 프록시({upstream_proxy})를 업스트림 프록시로 설정합니다.")

        # ####################################################################
        # ## (수정) 로그 레벨을 'debug'로 변경하여 모든 로그를 확인합니다. ##
        # ####################################################################
        common_args = [
            '--listen-port', str(self.port),
            '--set', f'confdir={self.mitm_dir}',
            '--set', 'termlog_level=debug', # 'error' -> 'debug' 로 변경
            # '--set', 'ssl_insecure=true',

            '-s', str(script_file)
        ]
        # ####################################################################

        # if upstream_proxy:
        #     common_args.extend(['--mode', f'upstream:{upstream_proxy}'])

        scripts_dir = Path(sys.executable).parent / "Scripts"
        commands_to_try = [
            [sys.executable, '-m', 'mitmproxy.tools.mitmdump'] + common_args,
            [str(scripts_dir / "mitmdump.exe")] + common_args,
            ['mitmdump'] + common_args,
        ]

        self.logger.info(f"프록시 서버를 시작합니다... (포트: {self.port})")

        # ################################################################
        # ## (수정) mitmproxy의 로그를 파일에 저장하기 위한 코드 추가 ##
        # ################################################################
        mitm_log_file_path = self.app_dir / "mitm_debug.log"
        self.logger.info(f"mitmproxy 디버그 로그를 다음 파일에 저장합니다: {mitm_log_file_path}")
        mitm_log_file = open(mitm_log_file_path, "w", encoding="utf-8")
        # ################################################################

        for i, cmd in enumerate(commands_to_try):
            if os.name != 'nt' and cmd[0].endswith('.exe'):
                continue
            self.logger.info(f"실행 시도 {i+1}/{len(commands_to_try)}: {cmd[0]}")
            try:
                creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                self.process = subprocess.Popen(
                    cmd,
                    # (수정) 로그를 파이프가 아닌 파일로 보냅니다.
                    stdout=mitm_log_file,
                    stderr=mitm_log_file,
                    creationflags=creation_flags
                )
                time.sleep(3)
                if self.process.poll() is None:
                    self.is_running = True
                    self.logger.info("프록시 서버가 성공적으로 시작되었습니다.")
                    return True
                else:
                    # 실패 시 로그 파일 내용을 읽어와서 보여줄 수 있습니다.
                    mitm_log_file.close() # 파일을 닫아야 읽을 수 있음
                    error_msg = Path(mitm_log_file_path).read_text(encoding="utf-8")
                    self.logger.warning(f"시도 {i+1} 실패:\n{error_msg}")
                    # 다음 시도를 위해 파일을 다시 엽니다.
                    mitm_log_file = open(mitm_log_file_path, "w", encoding="utf-8")

            except FileNotFoundError:
                self.logger.warning(f"시도 {i+1} 실패: '{cmd[0]}' 명령을 찾을 수 없습니다.")
            except Exception as e:
                self.logger.error(f"시도 {i+1} 중 예외 발생: {e}")

        mitm_log_file.close() # 모든 시도 실패 후 파일 닫기
        self.logger.error("모든 방법으로 프록시 시작에 실패했습니다.")
        return False

    def stop_proxy(self):
        """실행 중인 프록시 프로세스 종료"""
        if not self.is_running or not self.process:
            return
        
        self.logger.info("프록시 서버를 중지합니다...")
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.logger.warning("프록시가 정상 종료되지 않아 강제 종료합니다.")
            self.process.kill()
        self.is_running = False
        self.logger.info("프록시 서버가 중지되었습니다.")
    
    def install_certificate(self):
        """mitmproxy CA 인증서를 Windows 신뢰된 루트 저장소에 설치"""
        if os.name != 'nt':
            self.logger.info("인증서 자동 설치는 Windows에서만 지원됩니다.")
            return

        cert_path = self.mitm_dir / "mitmproxy-ca-cert.pem"
        self.mitm_dir.mkdir(exist_ok=True)
        
        if not cert_path.exists():
            self.logger.info("mitmproxy 인증서 파일을 생성합니다...")
            try:
                proc = subprocess.run(
                    [sys.executable, '-m', 'mitmproxy.tools.mitmdump', '--set', f'confdir={self.mitm_dir}'],
                    timeout=5, capture_output=True
                )
            except subprocess.TimeoutExpired:
                pass
            if not cert_path.exists():
                self.logger.error("인증서 파일 생성에 실패했습니다. 인터넷 연결이 안 될 수 있습니다.")
                return

        self.logger.info("Windows 인증서 저장소에 mitmproxy CA를 설치합니다...")
        try:
            result = subprocess.run(
                ['certutil', '-user', '-verifystore', 'Root', 'mitmproxy'],
                capture_output=True, text=True
            )
            if 'mitmproxy' in result.stdout:
                self.logger.info("인증서가 이미 설치되어 있습니다.")
                return
            result = subprocess.run(
                ['certutil', '-user', '-addstore', 'Root', str(cert_path)],
                check=True, capture_output=True
            )
            self.logger.info("인증서 설치 성공! 이제 HTTPS 트래픽을 감지할 수 있습니다.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"인증서 설치 실패: {e.stderr.decode(errors='ignore')}")
        except FileNotFoundError:
            self.logger.error("'certutil' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")

    def set_system_proxy_windows(self, enable: bool):
        """Windows 시스템 프록시 설정 또는 복원"""
        if os.name != 'nt':
            return
        
        try:
            import winreg
            import ctypes
            
            INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            
            # --- 이 부분의 백업 로직이 위 함수로 이동했습니다 ---
            # 프록시 설정 변경
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_WRITE)
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{self.port}")
                self.logger.info(f"시스템 프록시 설정 -> 127.0.0.1:{self.port}")
            else: 
                settings = self.original_proxy_settings
                if settings: # settings가 None이 아닐 때만 복원
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, settings["ProxyEnable"])
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, settings["ProxyServer"])
                    self.logger.info("시스템 프록시를 원래 설정으로 복원합니다.")
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
                    self.logger.info("백업된 설정이 없어 시스템 프록시를 비활성화합니다.")

            winreg.CloseKey(key)
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception as e:
            self.logger.error(f"시스템 프록시 설정/복원 실패: {e}")