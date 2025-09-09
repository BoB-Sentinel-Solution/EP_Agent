#!/usr/bin/env python3
"""
완전 자동화된 LLM 프록시 매니저 (메인 실행 파일) - 콘솔 전용 버전
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
from firewall_manager import FirewallManager


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
        self.firewall_manager = FirewallManager()


        # self.tray_icon = None

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

    def auto_setup_and_run(self):
        """전체 자동 설정 및 프록시 실행 (콘솔 모드 전용)"""
        self.logger.info("--- LLM 프록시 자동 설정을 시작합니다 ---")
        self.load_config()

        # 1. 종료 시그널 핸들러 설정 (Ctrl+C 처리)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # 2. 필수 패키지 설치
        if not self.check_and_install_dependencies():
            return
        

        # ##################################################################
        # ## (추가) 방화벽 규칙 자동 추가 로직 ##
        # ##################################################################
        mitmdump_path = self.proxy_manager.find_mitmdump_executable()
        if mitmdump_path:
            self.logger.info(f"mitmdump 실행 파일 위치: {mitmdump_path}")
            rule_name = "LLM Proxy (mitmdump)"
            self.firewall_manager.add_inbound_rule_for_program(rule_name, mitmdump_path)
        else:
            self.logger.warning("mitmdump.exe를 찾을 수 없어 방화벽 규칙을 추가할 수 없습니다.")
            self.logger.warning("수동으로 '...\\Scripts\\mitmdump.exe'에 대한 인바운드 규칙을 허용해야 할 수 있습니다.")
        # ##################################################################


        # 3. mitmproxy CA 인증서 설치 
        self.proxy_manager.install_certificate()
        
        # 프록시 시작 전에 백업을 먼저 실행
        self.proxy_manager.backup_original_proxy()

        # 4. 트래픽 로깅 스크립트 생성
        script_file = self.traffic_logger.create_llm_logger_script()

        # 5. 프록시 서버 시작
        if self.proxy_manager.start_proxy(script_file):
            # 6. 시스템 프록시 설정
            self.proxy_manager.set_system_proxy_windows(enable=True)
            self.logger.info("모든 설정이 완료되었습니다. LLM API 요청을 기다립니다...")
            self.logger.info(f"JSON 로그 파일: {self.traffic_logger.json_log_file}")
            
            # --- GUI/콘솔 선택 로직 제거 및 콘솔 대기 로직으로 통일 ---
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
            self.logger.error("--- LLM 프록시 시작에 실패했습니다. ---")
            self.cleanup() # 실패 시에도 정리

    def cleanup(self):
        """프로그램 종료 시 모든 설정을 원상 복구"""
        self.logger.info("\n--- 정리 작업을 시작합니다 ---")
        self.proxy_manager.stop_proxy()
        self.proxy_manager.set_system_proxy_windows(enable=False)
        self.save_config()
        self.logger.info("모든 설정이 원래대로 복구되었습니다.")
        # --- GUI 관련 코드 제거 ---
        # if self.tray_icon:
        #     self.tray_icon.stop()

    def signal_handler(self, signum, frame):
        """Ctrl+C와 같은 종료 시그널을 처리"""
        self.logger.warning(f"종료 신호(Signal: {signum}) 감지! 안전하게 종료합니다.")
        self.cleanup()
        sys.exit(0)

    def check_and_install_dependencies(self):
        """필수 패키지 자동 설치 (GUI 패키지 제외)"""
        # --- GUI 관련 패키지('pillow', 'pystray') 설치 목록에서 제거 ---
        required_packages = ['mitmproxy']
        
        if getattr(sys, 'frozen', False):
            self.logger.info("EXE 모드: 의존성이 번들링되어 있습니다.")
            return True
        
        all_installed = True
        for package in required_packages:
            if not self.is_package_installed(package):
                self.logger.info(f"패키지 설치 중: {package}")
                try:
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', package],
                        capture_output=True, text=True, timeout=60
                    )
                    if result.returncode != 0:
                        self.logger.error(f"{package} 설치 실패: {result.stderr}")
                        all_installed = False
                except Exception as e:
                    self.logger.error(f"{package} 설치 중 예외 발생: {e}")
                    all_installed = False
        
        if all_installed:
            self.logger.info("모든 필수 패키지가 설치되었습니다.")
        return all_installed
    
    def is_package_installed(self, package_name: str) -> bool:
        """패키지가 설치되어 있고 import 가능한지 직접 확인"""
        try:
            if package_name == 'mitmproxy':
                import mitmproxy
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
                self.logger.warning("설정 파일이 손상되었거나 형식이 맞지 않습니다.")
    
    # --- GUI 관련 함수(create_tray_icon) 전체 제거 ---


def main():
    """스크립트의 메인 진입점. 최상위 오류 처리 기능 포함."""
    app = LLMProxyApp()

    try:
        # --- GUI/콘솔 분기 로직 제거 ---
        app.auto_setup_and_run()
        
    except KeyboardInterrupt:
        app.logger.info("사용자에 의해 프로그램이 종료되었습니다.")
        app.cleanup()

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        app.logger.critical(f"치명적인 오류가 발생하여 안전 모드를 발동합니다.\n{error_details}")
        app.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()