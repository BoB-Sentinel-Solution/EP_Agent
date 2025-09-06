#!/usr/bin/env python3
"""
완전 자동화된 LLM 프록시 매니저 (기능 개선 버전)
- 주요 기능:
  - Ctrl+C 입력 시 프록시 설정 원상 복구 및 안전 종료
  - 지정된 LLM API(OpenAI, Anthropic, Google 등) 트래픽만 선별하여 로깅
  - Windows CA 인증서 자동 설치 로직 강화로 인터넷 끊김 문제 해결
  - 방화벽 문제 발생 가능성에 대한 안내 추가
"""

import os
import sys
import json
import time
import signal
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict

# --- GUI 및 의존성 라이브러리 ---
try:
    import tkinter as tk
    from tkinter import messagebox
    import pystray
    from PIL import Image, ImageDraw
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class AutoLLMProxy:
    """LLM 트래픽 로깅을 위한 자동화 프록시 클래스"""
    
    def __init__(self):
        # --- 기본 경로 및 설정 ---
        self.app_dir = Path.home() / ".llm_proxy"
        self.config_file = self.app_dir / "config.json"
        self.log_file = self.app_dir / "llm_requests.log"
        self.json_log_file = self.app_dir / "llm_requests.json"
        self.mitm_dir = self.app_dir / ".mitmproxy"
        
        # --- 상태 변수 ---
        self.port: int = 8081
        self.process: Optional[subprocess.Popen] = None
        self.is_running: bool = False
        self.original_proxy_settings: Optional[Dict] = None
        self.tray_icon = None

        self.app_dir.mkdir(exist_ok=True)
        self.setup_logging()

    def setup_logging(self):
        """콘솔과 파일에 로그를 남기도록 로거 설정"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.app_dir / "proxy_manager.log", encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    # --- 핵심 기능: 설정, 실행, 종료 ---


    def auto_setup_and_run(self, use_gui=True):
        """전체 자동 설정 및 프록시 실행 (실행 모드 로직 강화)"""
        self.logger.info("--- 🚀 LLM 프록시 자동 설정을 시작합니다 ---")
        self.load_config()

        # 1. 종료 시그널 핸들러 설정 (Ctrl+C 처리)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # 2. 필수 패키지 설치
        if not self.check_and_install_dependencies():
            return

        # 3. mitmproxy CA 인증서 설치 (가장 중요!)
        self.install_certificate()

        # 4. 프록시 서버 시작
        if self.start_proxy():
            # 5. 시스템 프록시 설정
            self.set_system_proxy_windows(enable=True)
            self.logger.info("🎉 모든 설정이 완료되었습니다. LLM API 요청을 기다립니다...")
            self.logger.info(f"💾 JSON 로그 파일: {self.json_log_file}")
            
            # --- 실행 모드 결정 및 대기 ---
            # GUI 모드가 요청되었고, 라이브러리가 사용 가능한지 확인
            can_run_gui = use_gui and GUI_AVAILABLE
            
            if can_run_gui:
                self.logger.info("시스템 트레이 아이콘 모드로 실행합니다.")
                self.tray_icon = self.create_tray_icon()
                self.tray_icon.run() # 이 함수는 프로그램이 종료되지 않도록 계속 대기합니다.
            else:
                # GUI 모드를 원했지만 라이브러리가 없는 경우, 콘솔 모드로 강제 전환
                if use_gui and not GUI_AVAILABLE:
                    self.logger.warning("⚠️ GUI 라이브러리(tkinter, pystray)를 찾을 수 없어 콘솔 모드로 전환합니다.")
                
                self.logger.info("콘솔 모드로 실행 중입니다. 종료하려면 Ctrl+C를 누르세요.")
                try:
                    # Ctrl+C 신호를 받거나 프로세스가 중지될 때까지 무한 대기
                    while self.is_running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    # signal_handler가 처리하지만, 만약을 위한 예외 처리
                    pass
                finally:
                    # 루프가 어떤 이유로든 종료되면 항상 정리 작업 수행
                    self.cleanup()
        else:
            self.logger.error("--- ❌ LLM 프록시 시작에 실패했습니다. ---")
            self.cleanup() # 실패 시에도 정리

    def start_proxy(self) -> bool:
        """mitmdump를 백그라운드 프로세스로 실행 (다양한 실행 방법 시도)"""
        if self.is_running:
            self.logger.warning("⚠️ 프록시가 이미 실행 중입니다.")
            return False

        import socket
        from pathlib import Path
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

        script_file = self.create_llm_logger_script()
        
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
    def cleanup(self):
        """프로그램 종료 시 모든 설정을 원상 복구"""
        self.logger.info("\n--- 🧹 정리 작업을 시작합니다 ---")
        self.stop_proxy()
        self.set_system_proxy_windows(enable=False)
        self.logger.info("✅ 모든 설정이 원래대로 복구되었습니다.")
        if self.tray_icon:
            self.tray_icon.stop()

    def signal_handler(self, signum, frame):
        """Ctrl+C와 같은 종료 시그널을 처리"""
        self.logger.warning(f"종료 신호(Signal: {signum}) 감지! 안전하게 종료합니다.")
        self.cleanup()
        sys.exit(0)

    # --- 세부 기능: 프록시, 인증서, 로깅 스크립트 등 ---

    def start_proxy(self) -> bool:
        """mitmdump를 백그라운드 프로세스로 실행"""
        if self.is_running:
            self.logger.warning("⚠️ 프록시가 이미 실행 중입니다.")
            return False

        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]

        script_file = self.create_llm_logger_script()
        
        cmd = [
            sys.executable, '-m', 'mitmproxy.tools.mitmdump',
            '--listen-port', str(self.port),
            '--set', f'confdir={self.mitm_dir}',
            '--set', 'termlog_level=error', # 콘솔 로그 최소화
            '-s', str(script_file)
        ]
        
        self.logger.info(f"프록시 서버를 시작합니다... (포트: {self.port})")
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags
            )
            time.sleep(3) # 시작 대기

            if self.process.poll() is None:
                self.is_running = True
                self.logger.info("✅ 프록시 서버가 성공적으로 시작되었습니다.")
                return True
            else:
                _, stderr = self.process.communicate()
                self.logger.error(f"❌ 프록시 시작 실패: {stderr.decode(errors='ignore')}")
                return False
        except Exception as e:
            self.logger.error(f"❌ 프록시 실행 중 예외 발생: {e}")
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


    def create_llm_logger_script(self) -> Path:
        """지정된 LLM 서비스의 통신만 로깅하는 mitmproxy 스크립트 생성"""
        script_content = '''
import json
from pathlib import Path
from datetime import datetime
from mitmproxy import http

class LLMSelectiveLogger:
    def __init__(self):
        self.json_log_file = Path.home() / ".llm_proxy" / "llm_requests.json"
        
        # --- 🎯 로깅할 LLM 서비스 호스트 목록 ---
        self.LLM_HOSTS = {
            # OpenAI / ChatGPT
            "api.openai.com",
            # Anthropic / Claude
            "api.anthropic.com",
            # Google / Gemini, Vertex AI
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            # Groq
            "api.groq.com",
            # Cohere
            "api.cohere.ai",
            # DeepSeek
            "api.deepseek.com",
        }

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """요청 호스트가 지정된 LLM 목록에 있는지 확인"""
        return flow.request.pretty_host in self.LLM_HOSTS

    def response(self, flow: http.HTTPFlow):
        """응답이 완료되었을 때 LLM 요청인지 확인하고 로깅"""
        if not self.is_llm_request(flow) or not flow.response or not flow.response.content:
            return
        
        print(f"✅ LLM API 감지: {flow.request.pretty_host}")

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "host": flow.request.pretty_host,
            "url": flow.request.pretty_url,
        }

        try:
            log_entry["request_body"] = json.loads(flow.request.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["request_body"] = "Non-JSON or empty body"

        try:
            log_entry["response_body"] = json.loads(flow.response.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["response_body"] = "Non-JSON or empty body"

        with open(self.json_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2) + "\\n")

addons = [LLMSelectiveLogger()]
'''
        script_file = self.app_dir / "llm_logger.py"
        script_file.write_text(script_content, encoding='utf-8')
        return script_file

    # --- 유틸리티 및 시스템 설정 ---

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

    def check_and_install_dependencies(self):
        """필수 패키지 자동 설치"""
        try:
            import pkg_resources
            required = {'mitmproxy', 'pillow', 'pystray'}
            installed = {pkg.key for pkg in pkg_resources.working_set}
            if not (missing := required - installed):
                self.logger.info("✅ 필수 패키지가 모두 설치되어 있습니다.")
                return True
            
            self.logger.info(f"📦 누락된 패키지 설치 중: {missing}")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing],
                                  stdout=subprocess.DEVNULL)
            return True
        except Exception as e:
            self.logger.error(f"❌ 필수 패키지 설치 실패: {e}")
            return False
            
    def save_config(self):
        config = {"original_proxy_settings": self.original_proxy_settings}
        self.config_file.write_text(json.dumps(config, indent=2), encoding='utf-8')

    def load_config(self):
        if self.config_file.exists():
            try:
                config = json.loads(self.config_file.read_text(encoding='utf-8'))
                self.original_proxy_settings = config.get("original_proxy_settings")
            except (json.JSONDecodeError, KeyError):
                self.logger.warning("⚠️ 설정 파일이 손상되었거나 형식이 맞지 않습니다.")
    
    # --- GUI 관련 (선택 사항) ---
    def create_tray_icon(self):
        image = Image.new('RGB', (64, 64), 'black')
        draw = ImageDraw.Draw(image)
        draw.text((10, 24), "LLM", fill='lime')
        menu = pystray.Menu(
            pystray.MenuItem(f"LLM Proxy (Port: {self.port})", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("로그 폴더 열기", lambda: os.startfile(self.app_dir)),
            pystray.MenuItem("종료", self.signal_handler, signal.SIGTERM, None)
        )
        return pystray.Icon("llm_proxy", image, "LLM Proxy", menu)

def main():
    """스크립트의 메인 진입점"""
    # 명령줄 인수가 없으면 GUI 모드로 간주
    use_gui = len(sys.argv) == 1
    
    proxy = AutoLLMProxy()
    proxy.auto_setup_and_run(use_gui=use_gui)

if __name__ == "__main__":
    main()