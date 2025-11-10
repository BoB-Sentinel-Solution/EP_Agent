#!/usr/bin/env python3
"""
완전 자동화된 LLM 프록시 매니저 (메인 실행 파일) - 콘솔 전용 버전
- 주요 기능:
  - 가상 환경(venv) 자동 생성 및 해당 환경 내에서 스크립트 실행 보장
  - requirements.txt 기반으로 의존성 자동 설치
  - 자체 개발한 Sentinel 프록시 서버 실행 및 관리
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
from typing import Set # Set 타입 힌트는 표준 라이브러리이므로 그대로 유지

# --------------------------------------------------------------------------
# 가상 환경(venv) 관리 로직 (변경 없음)
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
            # Windows에서는 subprocess.run을 사용하여 현재 프로세스를 대체하지 않고 실행
            result = subprocess.run(cmd)
            sys.exit(result.returncode)
        else:
            # Unix 계열에서는 os.execv를 사용하여 현재 프로세스를 대체 (더 효율적)
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
        # Windows 인코딩 오류 해결을 위해 자식 프로세스(pip)가 UTF-8을 사용하도록 강제
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
        stderr_output = e.stderr if e.stderr else "No stderr output"
        print(f"pip STDERR:\n{stderr_output}")
        print("="*50 + "\n")
        sys.exit(1)

# --------------------------------------------------------------------------
# PROJECT_ROOT 정의 및 LLMProxyApp 클래스
# --------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

class LLMProxyApp:
    """Sentinel LLM 프록시 애플리케이션 메인 클래스"""
    
    # [수정] ProxyManager 클래스를 인자로 받도록 수정
    def __init__(self, ProxyManagerClass):
        # [수정] 설정 디렉토리 이름 변경
        self.app_dir = Path.home() / ".sentinel_proxy" 
        self.config_file = self.app_dir / "config.json"
        # ProxyManagerClass를 사용하여 인스턴스 생성
        self.proxy_manager = ProxyManagerClass(self.app_dir, project_root=PROJECT_ROOT)

        # MCP 설정 감시자 (디버깅 모드 - 서버 전송 없음)
        self.mcp_watcher = None

        self.app_dir.mkdir(exist_ok=True)
        self.setup_logging()

    def setup_logging(self):
        """로거 설정"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                # [수정] 로그 파일 이름 변경
                logging.FileHandler(self.app_dir / "sentinel_manager.log", encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def auto_setup_and_run(self):
        """전체 자동 설정 및 프록시 실행"""
        self.logger.info("--- Sentinel LLM 프록시 자동 설정을 시작합니다 ---")
        self.load_config()

        # ========================================
        # [MCP 설정] watchdog 의존성 설치 후 import
        # ========================================
        # 이 부분은 원래 코드의 흐름을 따르며, import가 실패하면 오류가 발생합니다.
        try:
            # 의존성 설치 후 이 모듈들이 로드 가능합니다.
            from mcp_config.mcp_watcher import MCPConfigWatcher 
            from mcp_config.mcp_sender import MCPConfigSender # 주석 해제 시 사용 가능
        except ImportError as e:
            self.logger.warning(f"MCPConfigWatcher/Sender 모듈을 로드할 수 없습니다. 관련 기능은 비활성화됩니다: {e}")
            # 더미 클래스 정의
            class MCPDummyWatcher:
                def start(self): return False
                def is_running(self): return False
                def stop(self): pass
            MCPConfigWatcher = MCPDummyWatcher 


        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # venv 내 python.exe 경로
        if sys.platform == "win32":
            venv_python_exe = VENV_DIR / "Scripts" / "python.exe"
        else:
            venv_python_exe = VENV_DIR / "bin" / "python"

        # [제거] mitmdump 경로 확인 로직 제거
        
        # [수정] 프록시 Rule 이름 변경
        rule_name = "Sentinel Proxy" 
        self.logger.info(f"자체 프록시 서버 실행 파일: {venv_python_exe}")
        
        # 1. CA 인증서 생성 및 설치 (CertificateManager에서 Sentinel 이름 사용)
        self.proxy_manager.install_certificate()
        # 2. 기존 시스템 프록시 설정 백업
        self.proxy_manager.backup_original_proxy()

        # Sentinel 자체 프록시 서버 스크립트 경로
        script_file = PROJECT_ROOT / "sentinel_proxy" / "proxy_server.py"
        if not script_file.exists():
            self.logger.critical(f"CRITICAL: Sentinel 프록시 서버 스크립트({script_file})를 찾을 수 없습니다.")
            sys.exit(1)

        # 감시 대상 호스트 목록
        monitored_hosts = self._get_monitored_hosts()

        # 3. Sentinel 프록시 시작 (mitmdump + addon)
        if self.proxy_manager.start_proxy(script_file, str(venv_python_exe), monitored_hosts):
            # 4. 시스템 프록시 설정
            self.proxy_manager.set_system_proxy_windows(enable=True)

            # MCP 설정 파일 감시 시작 (디버깅 모드)
            self.logger.info("--- MCP 설정 파일 감시 시작 (디버깅 모드) ---")
            self.mcp_watcher = MCPConfigWatcher()
            if self.mcp_watcher.start():
                self.logger.info("✓ MCP 설정 감시가 활성화되었습니다. (JSON 출력 모드)")
            else:
                self.logger.warning("⚠ MCP 설정 감시를 시작하지 못했습니다. (MCPConfigWatcher 로드 실패)")

            self.logger.info("모든 설정이 완료되었습니다. LLM API 요청을 기다립니다...")
            self.logger.info(f"종료하려면 Ctrl+C를 누르세요.")
            try:
                # 프록시 서버가 실행 중인 동안 대기
                while self.proxy_manager.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                self.cleanup()
        else:
            self.logger.error("--- Sentinel LLM 프록시 시작에 실패했습니다. ---")
            self.cleanup()

    def _get_monitored_hosts(self) -> Set[str]:
        """
        감시 대상 호스트 목록 반환 (자체 프록시 서버 --allow-hosts용)
        """
        return {
            # LLM 호스트
            "chatgpt.com",
            "oaiusercontent.com",
            "claude.ai",  # 프록시 헤더 제거로 Cloudflare 우회
            "gemini.google.com",
            "chat.deepseek.com",
            "groq.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "api.openai.com",
            "api.anthropic.com",
            "api.groq.com",
            "api.cohere.ai",
            "api.deepseek.com",

            # App/MCP 호스트 (Cursor)
            "cursor.sh", 
            "api.individual.githubcopilot.com", 
            "api.individual.githubcopilot"
        }

    def cleanup(self):
        """프로그램 종료 시 모든 설정을 원상 복구"""
        self.logger.info("\n--- 정리 작업을 시작합니다 ---")

        # MCP 설정 감시 중지
        if self.mcp_watcher is not None and hasattr(self.mcp_watcher, 'is_running') and self.mcp_watcher.is_running():
            self.mcp_watcher.stop()

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
    # 1. 의존성 설치/확인
    setup_dependencies()
    
    # 2. 의존성 설치 후, 필요한 모듈을 동적으로 가져옵니다.
    try:
        # 이 시점에서 proxy.proxy_manager 및 그 내부의 certificate_manager가 로드됩니다.
        from proxy.proxy_manager import ProxyManager 
    except ImportError as e:
        # Venv 내 설치를 완료했음에도 임포트 실패는 설치 자체의 오류를 의미합니다.
        logging.critical(f"CRITICAL: 핵심 모듈 로드 실패 (설치/경로 오류 확인 필요): {e}")
        sys.exit(1)
        
    # 3. ProxyManager 클래스를 LLMProxyApp 생성자에 전달
    app = LLMProxyApp(ProxyManager) 
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
