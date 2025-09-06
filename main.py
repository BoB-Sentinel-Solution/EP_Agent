#!/usr/bin/env python3
"""
완전 자동화된 LLM 프록시 매니저 (메인 실행 파일)
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
from typing import Optional, Dict

# 모듈 import
from proxy_manager import ProxyManager
from traffic_logger import TrafficLogger

# --- GUI 및 의존성 라이브러리 ---
try:
    import tkinter as tk
    from tkinter import messagebox
    import pystray
    from PIL import Image, ImageDraw
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


class LLMProxyApp:
    """LLM 프록시 애플리케이션 메인 클래스"""
    
    def __init__(self):
        # --- 기본 경로 및 설정 ---
        self.app_dir = Path.home() / ".llm_proxy"
        self.config_file = self.app_dir / "config.json"
        self.log_file = self.app_dir / "llm_requests.log"
        
        # --- 컴포넌트 초기화 ---
        self.proxy_manager = ProxyManager(self.app_dir)
        self.traffic_logger = TrafficLogger(self.app_dir)
        
        # --- GUI 관련 ---
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
        self.proxy_manager.install_certificate()

        # 4. 트래픽 로깅 스크립트 생성
        script_file = self.traffic_logger.create_llm_logger_script()

        # 5. 프록시 서버 시작
        if self.proxy_manager.start_proxy(script_file):
            # 6. 시스템 프록시 설정
            self.proxy_manager.set_system_proxy_windows(enable=True)
            self.logger.info("🎉 모든 설정이 완료되었습니다. LLM API 요청을 기다립니다...")
            self.logger.info(f"💾 JSON 로그 파일: {self.traffic_logger.json_log_file}")
            
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
                    while self.proxy_manager.is_running:
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

    def cleanup(self):
        """프로그램 종료 시 모든 설정을 원상 복구"""
        self.logger.info("\n--- 🧹 정리 작업을 시작합니다 ---")
        self.proxy_manager.stop_proxy()
        self.proxy_manager.set_system_proxy_windows(enable=False)
        self.save_config()
        self.logger.info("✅ 모든 설정이 원래대로 복구되었습니다.")
        if self.tray_icon:
            self.tray_icon.stop()

    def signal_handler(self, signum, frame):
        """Ctrl+C와 같은 종료 시그널을 처리"""
        self.logger.warning(f"종료 신호(Signal: {signum}) 감지! 안전하게 종료합니다.")
        self.cleanup()
        sys.exit(0)

    def check_and_install_dependencies(self):
        """필수 패키지 자동 설치 (안전한 버전)"""
        required_packages = ['mitmproxy', 'pillow', 'pystray']
        
        # EXE 모드에서는 의존성 체크 건너뛰기
        if getattr(sys, 'frozen', False):
            self.logger.info("✅ EXE 모드: 의존성이 번들링되어 있습니다.")
            return True
        
        # 개발 모드에서만 의존성 설치
        all_installed = True
        for package in required_packages:
            if not self._is_package_installed(package):
                self.logger.info(f"📦 패키지 설치 중: {package}")
                try:
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', package],
                        capture_output=True,
                        text=True,
                        timeout=60  # 60초 타임아웃
                    )
                    
                    if result.returncode != 0:
                        self.logger.error(f"❌ {package} 설치 실패: {result.stderr}")
                        all_installed = False
                        continue
                    
                    # 설치 후 다시 확인 (최대 3초 대기)
                    time.sleep(1)
                    if self._is_package_installed(package):
                        self.logger.info(f"✅ {package} 설치 완료")
                    else:
                        self.logger.error(f"❌ {package} 설치 후에도 import 불가")
                        all_installed = False
                        
                except subprocess.TimeoutExpired:
                    self.logger.error(f"❌ {package} 설치 시간 초과 (60초)")
                    all_installed = False
                except Exception as e:
                    self.logger.error(f"❌ {package} 설치 중 예외 발생: {e}")
                    all_installed = False
        
        if all_installed:
            self.logger.info("✅ 모든 필수 패키지가 설치되었습니다.")
        else:
            self.logger.error("❌ 일부 패키지 설치에 실패했습니다.")
            
        return all_installed
    
    def _is_package_installed(self, package_name: str) -> bool:
        """패키지가 설치되어 있고 import 가능한지 직접 확인"""
        try:
            if package_name == 'mitmproxy':
                import mitmproxy
            elif package_name == 'pillow':
                import PIL
            elif package_name == 'pystray':
                import pystray
            return True
        except ImportError:
            return False
            
    def save_config(self):
        """설정을 파일에 저장"""
        config = {"original_proxy_settings": self.proxy_manager.original_proxy_settings}
        self.config_file.write_text(json.dumps(config, indent=2), encoding='utf-8')

    def load_config(self):
        """파일에서 설정을 로드"""
        if self.config_file.exists():
            try:
                config = json.loads(self.config_file.read_text(encoding='utf-8'))
                self.proxy_manager.original_proxy_settings = config.get("original_proxy_settings")
            except (json.JSONDecodeError, KeyError):
                self.logger.warning("⚠️ 설정 파일이 손상되었거나 형식이 맞지 않습니다.")
    
    # --- GUI 관련 (선택 사항) ---
    def create_tray_icon(self):
        """시스템 트레이 아이콘 생성"""
        image = Image.new('RGB', (64, 64), 'black')
        draw = ImageDraw.Draw(image)
        draw.text((10, 24), "LLM", fill='lime')
        menu = pystray.Menu(
            pystray.MenuItem(f"LLM Proxy (Port: {self.proxy_manager.port})", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("로그 폴더 열기", lambda: os.startfile(self.app_dir)),
            pystray.MenuItem("종료", lambda: self.signal_handler(signal.SIGTERM, None))
        )
        return pystray.Icon("llm_proxy", image, "LLM Proxy", menu)


def main():
    """스크립트의 메인 진입점. 최상위 오류 처리 기능 포함."""
    app = LLMProxyApp()

    try:
        # -----------------------------------------------
        # ## 메인 프로그램 로직 실행 ##
        # -----------------------------------------------
        # 명령줄 인수가 없으면 GUI 모드로 간주
        use_gui = len(sys.argv) == 1
        app.auto_setup_and_run(use_gui=use_gui)
        
    except KeyboardInterrupt:
        # 사용자가 Ctrl+C로 직접 종료한 경우는 정상 종료로 간주
        app.logger.info("사용자에 의해 프로그램이 종료되었습니다.")
        # cleanup은 signal_handler에서 이미 처리되므로 여기선 호출하지 않아도 됩니다.

    except Exception as e:
        # -----------------------------------------------
        # ## 예상치 못한 모든 오류 발생 시 실행되는 안전 장치 ##
        # -----------------------------------------------
        import traceback
        
        # 1. 치명적인 오류 로그 기록
        error_details = traceback.format_exc()
        app.logger.critical(f"💥 치명적인 오류가 발생하여 안전 모드를 발동합니다.\n{error_details}")
        
        # 2. 모든 설정 원상 복구
        app.cleanup()
        
        # 3. 프로그램 강제 종료 (오류 코드로 종료)
        sys.exit(1)


if __name__ == "__main__":
    main()