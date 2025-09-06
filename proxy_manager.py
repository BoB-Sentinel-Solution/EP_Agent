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
        
    def start_proxy(self, script_file: Path) -> bool:
        """mitmdump를 백그라운드 프로세스로 실행 (다양한 실행 방법 시도)"""
        if self.is_running:
            self.logger.warning("⚠️ 프록시가 이미 실행 중입니다.")
            return False

        # 동적 포트 할당
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

        # --- 다양한 환경에 대응하기 위한 mitmdump 실행 명령어 목록 ---
        common_args = [
            '--listen-port', str(self.port),
            '--set', f'confdir={self.mitm_dir}',
            '--set', 'termlog_level=error',
            '-s', str(script_file)
        ]
        
        # Scripts 폴더 경로 (Windows 가상환경 등)
        scripts_dir = Path(sys.executable).parent / "Scripts"

        commands_to_try = [
            # 1. Python 모듈로 실행 (가장 안정적)
            [sys.executable, '-m', 'mitmproxy.tools.mitmdump'] + common_args,
            # 2. Python 실행파일과 동일한 경로의 Scripts 폴더에서 직접 실행 (Windows 가상환경 대응)
            [str(scripts_dir / "mitmdump.exe")] + common_args,
            # 3. 시스템 PATH에 등록된 mitmdump 실행
            ['mitmdump'] + common_args,
        ]

        self.logger.info(f"프록시 서버를 시작합니다... (포트: {self.port})")
        for i, cmd in enumerate(commands_to_try):
            # Windows가 아닌데 .exe를 실행하려는 경우 건너뛰기
            if os.name != 'nt' and cmd[0].endswith('.exe'):
                continue

            self.logger.info(f"실행 시도 {i+1}/{len(commands_to_try)}: {cmd[0]}")
            try:
                creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creation_flags
                )
                time.sleep(3)

                if self.process.poll() is None:
                    self.is_running = True
                    self.logger.info("✅ 프록시 서버가 성공적으로 시작되었습니다.")
                    return True
                else:
                    _, stderr = self.process.communicate()
                    error_msg = stderr.decode(errors='ignore').strip()
                    if error_msg:
                        self.logger.warning(f"⚠️ 시도 {i+1} 실패: {error_msg}")

            except FileNotFoundError:
                self.logger.warning(f"⚠️ 시도 {i+1} 실패: '{cmd[0]}' 명령을 찾을 수 없습니다.")
            except Exception as e:
                self.logger.error(f"❌ 시도 {i+1} 중 예외 발생: {e}")
        
        self.logger.error("❌ 모든 방법으로 프록시 시작에 실패했습니다.")
        self.logger.error("   mitmproxy가 올바르게 설치되었는지, PATH에 등록되었는지 확인해주세요.")
        self.logger.error("   터미널에서 'pip show mitmproxy' 명령어로 설치 위치를 확인할 수 있습니다.")
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
            self.logger.warning("⚠️ 프록시가 정상 종료되지 않아 강제 종료합니다.")
            self.process.kill()
        self.is_running = False
        self.logger.info("✅ 프록시 서버가 중지되었습니다.")
    
    def install_certificate(self):
        """mitmproxy CA 인증서를 Windows 신뢰된 루트 저장소에 설치"""
        if os.name != 'nt':
            self.logger.info("인증서 자동 설치는 Windows에서만 지원됩니다.")
            return

        cert_path = self.mitm_dir / "mitmproxy-ca-cert.pem"
        self.mitm_dir.mkdir(exist_ok=True)
        
        # 1. 인증서 파일 생성 (없을 경우에만)
        if not cert_path.exists():
            self.logger.info("mitmproxy 인증서 파일을 생성합니다...")
            try:
                proc = subprocess.run(
                    [sys.executable, '-m', 'mitmproxy.tools.mitmdump', '--set', f'confdir={self.mitm_dir}'],
                    timeout=5, capture_output=True
                )
            except subprocess.TimeoutExpired:
                # 인증서 생성 후 프로세스는 자동으로 종료되지 않으므로 타임아웃은 정상
                pass
            
            if not cert_path.exists():
                self.logger.error("❌ 인증서 파일 생성에 실패했습니다. 인터넷 연결이 안 될 수 있습니다.")
                return

        # 2. Windows 인증서 저장소에 설치
        self.logger.info("Windows 인증서 저장소에 mitmproxy CA를 설치합니다...")
        try:
            # certutil 명령으로 인증서가 이미 설치되었는지 확인
            result = subprocess.run(
                ['certutil', '-user', '-verifystore', 'Root', 'mitmproxy'],
                capture_output=True, text=True
            )
            if 'mitmproxy' in result.stdout:
                self.logger.info("✅ 인증서가 이미 설치되어 있습니다.")
                return

            # 설치되지 않았다면 설치 진행
            result = subprocess.run(
                ['certutil', '-user', '-addstore', 'Root', str(cert_path)],
                check=True, capture_output=True
            )
            self.logger.info("✅ 인증서 설치 성공! 이제 HTTPS 트래픽을 감지할 수 있습니다.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"❌ 인증서 설치 실패: {e.stderr.decode(errors='ignore')}")
            self.logger.error("   이 문제 해결 전까지 인터넷 연결이 불안정할 수 있습니다.")
            self.logger.warning("   권한 문제일 수 있습니다. 관리자 권한으로 터미널을 다시 실행해보세요.")
        except FileNotFoundError:
            self.logger.error("❌ 'certutil' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")

    def set_system_proxy_windows(self, enable: bool):
        """Windows 시스템 프록시 설정 또는 복원"""
        if os.name != 'nt':
            return
        
        try:
            import winreg
            import ctypes
            
            INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ)

            # 설정 변경 전 현재 상태 백업 (최초 1회)
            if self.original_proxy_settings is None:
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    server, enabled = "", 0
                self.original_proxy_settings = {"ProxyServer": server, "ProxyEnable": enabled}
                self.logger.info(f"기존 프록시 설정 백업: {self.original_proxy_settings}")
            winreg.CloseKey(key)

            # 프록시 설정 변경
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_WRITE)
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{self.port}")
                self.logger.info(f"시스템 프록시 설정 -> 127.0.0.1:{self.port}")
            else: # 복원
                settings = self.original_proxy_settings
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, settings["ProxyEnable"])
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, settings["ProxyServer"])
                self.logger.info("시스템 프록시를 원래 설정으로 복원합니다.")
            winreg.CloseKey(key)

            # 변경 사항 즉시 적용
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception as e:
            self.logger.error(f"❌ 시스템 프록시 설정/복원 실패: {e}")