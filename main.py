#!/usr/bin/env python3
"""
완전 자동화된 LLM 프록시 매니저 (메인 실행 파일) - 콘솔 전용 버전
- 주요 기능:
  - 가상 환경(venv) 자동 생성 및 해당 환경 내에서 스크립트 실행 보장
  - requirements.txt 기반으로 의존성 자동 설치
  - Ctrl+C 입력 시 프록시 설정 원상 복구 및 안전 종료
"""

import os
import sys
import json
import time
import signal
import logging
import subprocess
from pathlib import Path

# --------------------------------------------------------------------------
# 가상 환경(venv) 관리 로직
# --------------------------------------------------------------------------
VENV_DIR = Path(__file__).resolve().parent / "venv"

def is_in_venv():
    """현재 스크립트가 venv 내에서 실행 중인지 확인합니다."""
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)

def bootstrap_venv():
    """
    가상 환경을 확인/생성하고, 스크립트를 venv 내에서 재실행합니다.
    """
    if is_in_venv():
        return True

    print("INFO: 시스템 파이썬으로 실행되었습니다. 가상 환경을 설정합니다.")

    if not VENV_DIR.is_dir():
        print(f"INFO: '{VENV_DIR}'에 가상 환경을 생성합니다...")
        try:
            subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        except subprocess.CalledProcessError as e:
            print(f"CRITICAL: 가상 환경 생성에 실패했습니다: {e}")
            sys.exit(1)

    if sys.platform == "win32":
        venv_python_exe = VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python_exe = VENV_DIR / "bin" / "python"

    if not venv_python_exe.exists():
        print(f"CRITICAL: 가상 환경에서 파이썬 실행 파일({venv_python_exe})을 찾을 수 없습니다.")
        sys.exit(1)

    print(f"INFO: '{venv_python_exe}'를 사용하여 스크립트를 재시작합니다...")
    cmd = [str(venv_python_exe), __file__] + sys.argv[1:]
    
    try:
        if sys.platform == "win32":
            result = subprocess.run(cmd)
            sys.exit(result.returncode)
        else:
            os.execv(venv_python_exe, cmd)
    except Exception as e:
        print(f"CRITICAL: 가상 환경 내에서 스크립트를 재시작하는 데 실패했습니다: {e}")
        sys.exit(1)

def setup_dependencies():
    """requirements.txt를 읽어 필요한 패키지를 설치합니다."""
    if getattr(sys, 'frozen', False): return

    requirements_path = Path(__file__).resolve().parent / 'requirements.txt'
    if not requirements_path.exists():
        print(f"WARNING: '{requirements_path}'가 없어 의존성 검사를 건너뜁니다.")
        return

    print("INFO: requirements.txt 기반으로 필수 패키지를 설치합니다...")
    try:
        # [수정] Windows 인코딩 오류 해결을 위해 자식 프로세스(pip)가 UTF-8을 사용하도록 강제
        env = os.environ.copy()
        env['PYTHONUTF8'] = '1'

        # sys.executable은 항상 venv 내부의 파이썬을 가리킵니다.
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_path)],
            check=True, capture_output=True, text=True, encoding='utf-8', env=env
        )
        print("INFO: 모든 필수 패키지가 준비되었습니다.")
    except subprocess.CalledProcessError as e:
        print("\n" + "="*50)
        print("CRITICAL: 필수 패키지 설치에 실패했습니다.")
        # stderr이 None이거나 바이트 스트링일 수 있으므로 안전하게 디코딩
        stderr_output = e.stderr if e.stderr else "No stderr output"
        print(f"pip STDERR:\n{stderr_output}")
        print("="*50 + "\n")
        sys.exit(1)

# --------------------------------------------------------------------------
# 의존성 설치 후 모듈 import
# --------------------------------------------------------------------------
from proxy.proxy_manager import ProxyManager
from traffic_logger import TrafficLogger

PROJECT_ROOT = Path(__file__).resolve().parent

class LLMProxyApp:
    """LLM 프록시 애플리케이션 메인 클래스"""
    
    def __init__(self):
        self.app_dir = Path.home() / ".llm_proxy"
        self.config_file = self.app_dir / "config.json"
        self.proxy_manager = ProxyManager(self.app_dir, project_root=PROJECT_ROOT)
        self.traffic_logger = TrafficLogger(self.app_dir, project_root=PROJECT_ROOT)

        self.app_dir.mkdir(exist_ok=True)
        self.setup_logging()

    def setup_logging(self):
        """로거 설정"""
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
        """전체 자동 설정 및 프록시 실행"""
        self.logger.info("--- LLM 프록시 자동 설정을 시작합니다 ---")
        self.load_config()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # venv 내 python.exe 경로 (Windows 기준)
        if sys.platform == "win32":
            venv_python_exe = VENV_DIR / "Scripts" / "python.exe"
            mitmdump_path = VENV_DIR / "Scripts" / "mitmdump.exe"
        else:
            venv_python_exe = VENV_DIR / "bin" / "python"
            mitmdump_path = VENV_DIR / "bin" / "mitmdump"

        if not mitmdump_path.exists():
            self.logger.critical(f"CRITICAL: 가상 환경에서 mitmdump({mitmdump_path})를 찾을 수 없습니다.")
            self.logger.critical("'mitmproxy'가 requirements.txt에 포함되어 있는지 확인하세요.")
            sys.exit(1)
        
        self.logger.info(f"mitmdump 실행 파일 위치: {mitmdump_path}")
        
        rule_name = "LLM Proxy (mitmdump)"
        
        self.proxy_manager.install_certificate()
        self.proxy_manager.backup_original_proxy()
        
        script_file = self.traffic_logger.get_script_file_path()
        monitored_hosts = self.traffic_logger.get_all_monitored_hosts()

        if self.proxy_manager.start_proxy(script_file, str(venv_python_exe), monitored_hosts):
            self.proxy_manager.set_system_proxy_windows(enable=True)
            self.logger.info("모든 설정이 완료되었습니다. LLM API 요청을 기다립니다...")
            self.logger.info(f"종료하려면 Ctrl+C를 누르세요.")
            try:
                while self.proxy_manager.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                self.cleanup()
        else:
            self.logger.error("--- LLM 프록시 시작에 실패했습니다. ---")
            self.cleanup()

    def cleanup(self):
        """프로그램 종료 시 모든 설정을 원상 복구"""
        self.logger.info("\n--- 정리 작업을 시작합니다 ---")
        self.proxy_manager.stop_proxy()
        self.proxy_manager.set_system_proxy_windows(enable=False)
        self.save_config()
        self.logger.info("모든 설정이 원래대로 복구되었습니다.")

    def signal_handler(self, signum, frame):
        """종료 시그널 처리"""
        self.logger.warning(f"종료 신호(Signal: {signum}) 감지! 안전하게 종료합니다.")
        self.cleanup()
        sys.exit(0)

    def save_config(self):
        config = {"original_proxy_settings": self.proxy_manager.original_proxy_settings}
        self.config_file.write_text(json.dumps(config, indent=2), encoding='utf-8')

    def load_config(self):
        if self.config_file.exists():
            try:
                config = json.loads(self.config_file.read_text(encoding='utf-8'))
                self.proxy_manager.original_proxy_settings = config.get("original_proxy_settings")
            except (json.JSONDecodeError, KeyError):
                self.logger.warning("설정 파일이 손상되었거나 형식이 맞지 않습니다.")

def main():
    """메인 진입점"""
    setup_dependencies()
    app = LLMProxyApp()
    try:
        app.auto_setup_and_run()
    except Exception:
        import traceback
        error_details = traceback.format_exc()
        logging.critical(f"치명적인 오류 발생. 정리 작업을 시도합니다.\n{error_details}")
        app.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    bootstrap_venv()
    main()

