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
import re  
from pathlib import Path
from typing import Optional, Dict
from locale import getpreferredencoding


class ProxyManager:
    """프록시 서버 실행 및 시스템 프록시 설정을 담당하는 클래스"""

    def __init__(self, app_dir: Path, project_root: Path):
        self.app_dir = app_dir
        self.mitm_dir = app_dir / ".mitmproxy"
        self.port: int = 8081
        self.process: Optional[subprocess.Popen] = None
        self.is_running: bool = False
        self.original_proxy_settings: Optional[Dict] = None
        self.logger = logging.getLogger(__name__)
        self.project_root = project_root


   

    def find_mitmdump_executable(self) -> Optional[str]:
        """실행 가능한 mitmdump의 전체 경로를 찾고, 없으면 설치를 시도합니다."""
        
        # 1. 먼저 mitmproxy 모듈이 설치되어 있는지 확인
        try:
            subprocess.run([sys.executable, '-c', 'import mitmproxy'], 
                        check=True, capture_output=True, timeout=5)
            self.logger.info("mitmproxy 모듈이 설치되어 있습니다.")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.logger.warning("mitmproxy가 설치되지 않았습니다. 설치를 시도합니다...")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', 'mitmproxy'], 
                            check=True, capture_output=True)
                self.logger.info("mitmproxy 설치 완료!")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"mitmproxy 설치 실패: {e}")
                return None

        # 2. 시스템 PATH에서 찾기
        if os.name == 'nt':
            try:
                result = subprocess.run(
                    ['where', 'mitmdump'], capture_output=True, text=True, check=True,
                    encoding=getpreferredencoding(), errors='ignore'
                )
                path = result.stdout.strip().split('\n')[0]
                if path and Path(path).exists():
                    self.logger.info(f"PATH에서 mitmdump 발견: {path}")
                    return path
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        # 3. 현재 Python의 Scripts 폴더에서 찾기
        scripts_dir = Path(sys.executable).parent / "Scripts"
        mitmdump_path = scripts_dir / "mitmdump.exe"
        if mitmdump_path.exists():
            self.logger.info(f"Scripts 폴더에서 mitmdump 발견: {mitmdump_path}")
            return str(mitmdump_path)

        # 4. Microsoft Store Python 경로들 탐색
        packages_dir = Path(os.path.expanduser('~')) / "AppData" / "Local" / "Packages"
        if packages_dir.exists():
            for package_dir in packages_dir.glob("PythonSoftwareFoundation.Python.*"):
                local_cache_scripts = package_dir / "LocalCache" / "local-packages" / "Python313" / "Scripts" / "mitmdump.exe"
                if local_cache_scripts.exists():
                    self.logger.info(f"MS Store 경로에서 mitmdump 발견: {local_cache_scripts}")
                    return str(local_cache_scripts)
        
        # 5. 직접 Python 모듈로 실행할 수 있는지 재확인
        try:
            result = subprocess.run([sys.executable, '-m', 'mitmproxy.tools.mitmdump', '--version'], 
                                capture_output=True, timeout=10)
            if result.returncode == 0:
                self.logger.info("Python 모듈로 mitmdump 실행 가능합니다.")
                return "python_module"  # 특별한 식별자
        except:
            pass
        
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




    def start_proxy(self, script_module: Path, venv_python_exe: str) -> bool:
        """
        지정된 경로의 mitmdump를 백그라운드 프로세스로 실행합니다.
        (복잡한 탐색 로직 제거, 단일 실행 방식)
        """
        if self.is_running:
            self.logger.warning("프록시가 이미 실행 중입니다.")
            return False

        # 동적으로 사용 가능한 포트 찾기
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

        # mitmdump 실행 파일 경로 찾기
        venv_dir = Path(venv_python_exe).parent.parent
        mitmdump_exe = venv_dir / "Scripts" / "mitmdump.exe"
        
        # mitmdump 실행에 필요한 공통 인자 설정
        common_args = [
            '--listen-port', str(self.port),
            '--set', f'confdir={self.mitm_dir}',
            '--set', 'termlog_level=debug', # 상세 로그를 위해 debug 레벨 유지
            '--set', 'websocket=true',  # WebSocket 지원 추가
            '--set', 'connection_strategy=lazy',  # 연결 최적화
            '--set', 'stream_large_bodies=1m',    # 큰 응답 스트리밍
            '--set', 'connection_timeout=20',      # 추가
            '--set', 'tcp_keep_alive=true',        # 추가
            '--set', 'server_connect_timeout=20',  # 추가
            '-s', str(script_module)
        ]

        command = [str(mitmdump_exe)] + common_args
        
        self.logger.info(f"프록시 서버를 시작합니다... (포트: {self.port})")
        self.logger.info(f"실행 명령어: {' '.join(command)}")

        # mitmproxy의 로그를 파일에 저장
        mitm_log_file_path = self.app_dir / "mitm_debug.log"
        self.logger.info(f"mitmproxy 디버그 로그를 다음 파일에 저장합니다: {mitm_log_file_path}")
        
        try:

            env = os.environ.copy()
            python_path = env.get('PYTHONPATH', '')
            # os.pathsep은 OS에 맞는 경로 구분자입니다 (Windows: ';', Linux/macOS: ':')
            env['PYTHONPATH'] = f"{self.project_root}{os.pathsep}{python_path}"
            
            
            mitm_log_file = open(mitm_log_file_path, "w", encoding="utf-8")
            
            # Windows에서 콘솔 창이 뜨지 않도록 설정
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            
            # mitmdump 프로세스 시작
            self.process = subprocess.Popen(
                command,
                stdout=mitm_log_file,
                stderr=subprocess.STDOUT,
                creationflags=creation_flags,
                encoding='utf-8',
                errors='replace',
                cwd=self.project_root,
                env=env 
            )
            
            # 프로세스가 안정적으로 시작될 시간을 줍니다.
            time.sleep(3)
            
            # 프로세스가 여전히 실행 중인지 확인
            if self.process.poll() is None:
                self.is_running = True
                self.logger.info("프록시 서버가 성공적으로 시작되었습니다.")
                # 성공 시에는 로그 파일을 닫지 않고 Popen이 관리하도록 둡니다.
                return True
            else:
                # 프로세스가 시작 직후 종료된 경우
                mitm_log_file.close() # 로그 파일 핸들을 닫아 파일 접근 보장
                with open(mitm_log_file_path, 'r', encoding='utf-8', errors='replace') as f:
                    error_content = f.read().strip()
                self.logger.warning(f"프록시 시작 실패 - 로그:\n{error_content[:500]}...")
                return False

        except FileNotFoundError:
            self.logger.error(f"명령을 실행할 수 없습니다: '{mitmdump_exe}' 파일을 찾을 수 없습니다.")
            return False
        except Exception as e:
            self.logger.error(f"프록시 시작 중 예외 발생: {e}")
            if 'mitm_log_file' in locals() and not mitm_log_file.closed:
                mitm_log_file.close()
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
        # 기존 코드 마지막에 추가
        # 로그 파일이 열려있다면 닫기
        try:
            if hasattr(self, '_mitm_log_file') and not self._mitm_log_file.closed:
                self._mitm_log_file.close()
        except:
            pass
    

    def install_certificate(self):
        """(개선) mitmproxy CA 인증서를 생성하고 Windows에 설치하는 강화된 로직"""
        if os.name != 'nt':
            self.logger.info("인증서 자동 설치는 Windows에서만 지원됩니다.")
            return

        cert_path = self.mitm_dir / "mitmproxy-ca-cert.pem"
        self.mitm_dir.mkdir(exist_ok=True)
        
        # --- (개선 1) 인증서 생성 로직 강화 ---
        if not cert_path.exists():
            self.logger.info("mitmproxy 인증서 파일을 생성합니다...")
            
            # 시도 1: Python 모듈로 실행
            cmd_list = [sys.executable, '-m', 'mitmproxy.tools.mitmdump', '--set', f'confdir={self.mitm_dir}']
            try:
                # 10초 후 타임아웃은 정상적인 동작으로 간주
                subprocess.run(cmd_list, timeout=10, capture_output=True,
                            encoding=getpreferredencoding(), errors='ignore')
            except subprocess.TimeoutExpired:
                pass # 성공
            except Exception as e:
                self.logger.warning(f"Python 모듈 방식의 인증서 생성 중 오류 발생: {e}")

            # 시도 1 후에도 파일이 없다면, 시도 2: 직접 실행 파일(.exe)로 실행
            if not cert_path.exists():
                self.logger.info("모듈 실행 방식 실패. 직접 실행 방식으로 다시 시도합니다...")
                mitmdump_exe = self.find_mitmdump_executable()
                if mitmdump_exe:
                    try:
                        subprocess.run([mitmdump_exe, '--set', f'confdir={self.mitm_dir}'], timeout=10)
                    except subprocess.TimeoutExpired:
                        pass # 성공
                    except Exception as e:
                        self.logger.error(f"직접 실행 방식의 인증서 생성 중 오류 발생: {e}")
                else:
                    self.logger.error("mitmdump.exe를 찾을 수 없어 인증서를 생성할 수 없습니다.")
            
            # 최종 확인
            if not cert_path.exists():
                self.logger.error("모든 방법으로 인증서 파일 생성에 실패했습니다. 인터넷 연결이 안 될 수 있습니다.")
                return

        # --- (개선 2) 인증서 설치 및 오류 처리 강화 ---
        self.logger.info("Windows 인증서 저장소에 mitmproxy CA를 설치합니다...")
        try:
            # 규칙이 이미 있는지 확인
            check_cmd = ['certutil', '-user', '-verifystore', 'Root', 'mitmproxy']
            result = subprocess.run(check_cmd, capture_output=True, text=True, encoding=getpreferredencoding())
            if "mitmproxy" in result.stdout and "찾을" not in result.stdout:
                self.logger.info("인증서가 이미 설치되어 있습니다.")
                return

            # 설치 실행
            add_cmd = ['certutil', '-user', '-addstore', 'Root', str(cert_path)]
            result = subprocess.run(add_cmd, check=True, capture_output=True, text=True, encoding=getpreferredencoding())
            self.logger.info("인증서 설치 성공! 이제 HTTPS 트래픽을 감지할 수 있습니다.")

        except FileNotFoundError:
            self.logger.error("'certutil' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"certutil 명령어 실행 실패! (관리자 권한으로 실행했는지 확인하세요)")
            self.logger.error(f"오류 내용: {e.stderr}")
 


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
                 # MCP localhost 우회 설정 추가
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.0.0.1;*.local;<local>")  
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