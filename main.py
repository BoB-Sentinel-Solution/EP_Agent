# 안녕
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
import hashlib
from pathlib import Path

# --------------------------------------------------------------------------
# 가상 환경(venv) 관리 로직
# --------------------------------------------------------------------------

def get_venv_dir():
    """venv 디렉토리 경로 반환 (exe일 때는 영구 경로 사용)"""
    if getattr(sys, 'frozen', False):
        # exe로 패킹된 경우: 홈 디렉토리에 영구 venv 생성
        return Path.home() / ".llm_proxy" / "venv"
    else:
        # 일반 python 스크립트: 프로젝트 폴더에 venv 생성
        return Path(__file__).resolve().parent / "venv"

VENV_DIR = get_venv_dir()

def is_in_venv():
    """현재 스크립트가 venv 내에서 실행 중인지 확인합니다."""
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)

def bootstrap_venv():
    """
    가상 환경을 확인/생성하고, 스크립트를 venv 내에서 재실행합니다.
    exe로 패킹된 경우는 시스템 환경을 사용합니다.
    """
    is_frozen = getattr(sys, 'frozen', False)

    # exe로 패킹된 경우: venv 없이 시스템 환경 사용
    if is_frozen:
        print("INFO: exe 모드로 실행됨. 시스템 환경을 사용합니다.")
        return True

    if is_in_venv():
        return True

    print(f"INFO: 시스템 파이썬으로 실행되었습니다. 가상 환경을 설정합니다.")

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
    is_frozen = getattr(sys, 'frozen', False)

    # exe 모드일 때는 임시 폴더(_MEIPASS)에서 requirements.txt 찾기
    if is_frozen:
        requirements_path = Path(sys._MEIPASS) / 'requirements.txt'
    else:
        requirements_path = Path(__file__).resolve().parent / 'requirements.txt'

    if not requirements_path.exists():
        print(f"WARNING: '{requirements_path}'가 없어 의존성 검사를 건너뜁니다.")
        return
    
    # #무결성 검사
    # EXPECTED_SHA256 = "a1363aac92bfce5952aac8aee6a6916cf1f1ab6fc6107da5104c69e8d5df685c"
    # print("INFO: requirements.txt 파일의 무결성을 검사합니다...")
    # try:
    #     h = hashlib.sha256()
    #     with open(requirements_path, 'rb') as f:
    #         while chunk := f.read(4096):
    #             h.update(chunk)
    #     actual_SHA256 = h.hexdigest()
    # except IOError as e:
    #     print(f"CRITICAL: requirements.txt 파일을 읽을 수 없습니다: {e}")
    #     sys.exit(1)

    # if actual_SHA256 != EXPECTED_SHA256:
    #     print("\n" + "="*50)
    #     print("CRITICAL: requirements.txt 파일이 변조되었거나 공식 버전과 다릅니다.")
    #     print(f"  > 기대 SHA256: {EXPECTED_SHA256}")
    #     print(f"  > 실제 SHA256: {actual_SHA256}")
    #     print("  > 보안을 위해 패키지 설치를 중단합니다.")
    #     print("="*50 + "\n")
    #     sys.exit(1)
    
    # print(f"INFO: 무결성 검사 통과 (SHA256: {actual_SHA256}).")
    
    # # ----------------------------------------------------무결성 검사 종료

    # exe 모드일 때는 시스템 Python 사용
    if is_frozen:
        import shutil
        python_exe = shutil.which("python")
        if not python_exe:
            print("WARNING: 시스템 Python을 찾을 수 없습니다. 의존성 설치를 건너뜁니다.")
            print("INFO: 수동으로 설치하세요: pip install mitmproxy watchdog")
            return
        print(f"INFO: 시스템 Python 사용: {python_exe}")
    else:
        # 일반 모드: venv 내부 Python 사용
        python_exe = sys.executable

    print("INFO: requirements.txt 기반으로 필수 패키지를 설치합니다...")
    print("INFO: (누락된 패키지만 설치됩니다. 시간이 걸릴 수 있습니다...)")
    try:
        # [수정] Windows 인코딩 오류 해결을 위해 자식 프로세스(pip)가 UTF-8을 사용하도록 강제
        env = os.environ.copy()
        env['PYTHONUTF8'] = '1'

        result = subprocess.run(
            [python_exe, '-m', 'pip', 'install', '-r', str(requirements_path)],
            check=True, capture_output=True, text=True, encoding='utf-8', env=env
        )

        # 새로 설치된 패키지가 있는지 확인
        needs_restart = False
        if result.stdout and "Successfully installed" in result.stdout:
            print("INFO: 새 패키지가 설치되었습니다.")
            needs_restart = True
        else:
            print("INFO: 모든 필수 패키지가 이미 설치되어 있습니다.")

        # exe 모드이고 새 패키지가 설치되었으면 재시작 필요
        if is_frozen and needs_restart:
            print("\n" + "="*50)
            print("INFO: 새 패키지 적용을 위해 프로그램을 재시작합니다...")
            print("="*50 + "\n")
            # 1초 대기 후 자기 자신 재실행
            time.sleep(1)
            subprocess.Popen([sys.executable] + sys.argv)
            sys.exit(0)  # 현재 프로세스 종료

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
from typing import Set
from proxy.proxy_manager import ProxyManager

PROJECT_ROOT = Path(__file__).resolve().parent

class LLMProxyApp:
    """LLM 프록시 애플리케이션 메인 클래스"""
    
    def __init__(self):
        self.app_dir = Path.home() / ".llm_proxy"
        self.config_file = self.app_dir / "config.json"
        self.proxy_manager = ProxyManager(self.app_dir, project_root=PROJECT_ROOT)

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
                def __init__(self, server_url=None, verify_tls=True):
                    pass  # 인자를 받지만 아무것도 하지 않음
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

        rule_name = "Sentinel Proxy"
        self.logger.info(f"자체 프록시 서버 실행 파일: {venv_python_exe}")
        
        self.proxy_manager.install_certificate()
        self.proxy_manager.backup_original_proxy()

        # 자체 프록시 서버 스크립트 경로
        script_file = PROJECT_ROOT / "sentinel_proxy" / "proxy_server.py"
        if not script_file.exists():
            self.logger.critical(f"CRITICAL: 프록시 서버 진입점 스크립트({script_file})를 찾을 수 없습니다.")
            sys.exit(1)

        # 감시 대상 호스트 목록
        monitored_hosts = self._get_monitored_hosts()

        # 자체 프록시 서버 시작
        if self.proxy_manager.start_proxy(script_file, str(venv_python_exe), monitored_hosts):
            self.proxy_manager.set_system_proxy_windows(enable=True)

            # MCP 설정 파일 감시 시작 (서버 전송 모드)
            self.logger.info("--- MCP 설정 파일 감시 시작 (서버 전송 모드) ---")
            mcp_server_url = "https://bobsentinel.site/api/mcp"
            self.mcp_watcher = MCPConfigWatcher(server_url=mcp_server_url, verify_tls=False)
            if self.mcp_watcher.start():
                self.logger.info(f"✓ MCP 설정 감시가 활성화되었습니다. (서버: {mcp_server_url})")
            else:
                self.logger.warning("⚠ MCP 설정 감시를 시작하지 못했습니다. (MCPConfigWatcher 로드 실패)")
            
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

    def _get_monitored_hosts(self) -> Set[str]:
        """
        감시 대상 호스트 목록 반환 (자체 프록시 서버 --allow-hosts용)
        dispatcher.py의 LLM_HOSTS + APP_HOSTS와 동일
        """
        return {
            # LLM 호스트
            "chatgpt.com",
            "oaiusercontent.com",  # ChatGPT 파일 업로드
            "claude.ai",
            "gemini.google.com",
            "push.clients6.google.com",  # Gemini 파일 업로드
            "googleusercontent.com",  # Gemini 이미지 (lh3.googleusercontent.com 포함)
            "play.google.com",  # Google 로깅
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
            "api.individual.githubcopilot.com",  # VSCode copilot
            "api.individual.githubcopilot"
        }

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