#!/usr/bin/env python3
"""
프록시 관리자 - mitmproxy 실행 관리
"""

import os
import time
import socket
import logging
import subprocess
from pathlib import Path
from typing import Optional, Set

from proxy.certificate_manager import CertificateManager
from proxy.system_proxy_manager import SystemProxyManager


class ProxyManager:
    """mitmproxy 프로세스 실행 및 관리"""

    def __init__(self, app_dir: Path, project_root: Path):
        self.app_dir = app_dir
        self.mitm_dir = app_dir / ".mitmproxy"
        self.port: int = 8081
        self.process: Optional[subprocess.Popen] = None
        self.is_running: bool = False
        self.logger = logging.getLogger(__name__)
        self.project_root = project_root

        # 하위 매니저 초기화
        self.cert_manager = CertificateManager(self.mitm_dir)
        self.system_proxy_manager = SystemProxyManager()

    @property
    def original_proxy_settings(self):
        """하위 호환성을 위한 프로퍼티"""
        return self.system_proxy_manager.original_proxy_settings

    @original_proxy_settings.setter
    def original_proxy_settings(self, value):
        """하위 호환성을 위한 세터"""
        self.system_proxy_manager.original_proxy_settings = value

    def backup_original_proxy(self):
        """시스템 프록시 설정 백업 (위임)"""
        self.system_proxy_manager.backup_original_proxy()

    def install_certificate(self):
        """인증서 설치 (위임)"""
        self.cert_manager.install_certificate()

    def set_system_proxy_windows(self, enable: bool):
        """시스템 프록시 설정 (위임)"""
        self.system_proxy_manager.set_system_proxy(enable, self.port if enable else None)

    def start_proxy(self, script_module: Path, venv_python_exe: str, allowed_hosts: Set[str] = None) -> bool:
        """mitmdump 프로세스를 백그라운드로 실행"""
        if self.is_running:
            self.logger.warning("프록시가 이미 실행 중입니다.")
            return False

        # 동적으로 사용 가능한 포트 찾기
        self.port = self._find_available_port()

        # mitmdump 실행 파일 경로
        venv_dir = Path(venv_python_exe).parent.parent
        mitmdump_exe = venv_dir / "Scripts" / "mitmdump.exe"

        # mitmdump 실행 인자 구성
        command_args = self._build_mitmdump_args(script_module, allowed_hosts)
        command = [str(mitmdump_exe)] + command_args

        self.logger.info(f"프록시 서버를 시작합니다... (포트: {self.port})")
        self.logger.info(f"실행 명령어: {' '.join(command)}")

        # 프로세스 실행
        return self._start_mitmdump_process(command)

    def stop_proxy(self):
        """실행 중인 mitmdump 프로세스 종료"""
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

    def _find_available_port(self) -> int:
        """사용 가능한 포트 동적 할당"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _build_mitmdump_args(self, script_module: Path, allowed_hosts: Set[str] = None) -> list:
        """mitmdump 실행 인자 생성"""
        args = [
            '--listen-port', str(self.port),
            '--set', f'confdir={self.mitm_dir}',
            '--set', 'termlog_level=debug',
            '--set', 'websocket=true',
            '--set', 'connection_strategy=lazy',
            '--set', 'stream_large_bodies=1m',
            '--set', 'connection_timeout=20',
            '--set', 'tcp_keep_alive=true',
            '--set', 'server_connect_timeout=20',
            '-s', str(script_module)
        ]

        # 허용된 호스트 패턴 추가
        if allowed_hosts:
            #patterns = [f".*{host.replace('.', r'\.')}" for host in allowed_hosts]
            patterns = [".*" + host.replace('.', r'\.') for host in allowed_hosts]

            allow_hosts_pattern = '|'.join(patterns)
            args.extend(['--allow-hosts', allow_hosts_pattern])

            self.logger.info(f"인터셉트 대상 호스트: {', '.join(sorted(allowed_hosts))}")
            self.logger.info(f"정규식 패턴: {allow_hosts_pattern[:200]}...")
            self.logger.info(f"나머지 호스트는 암복호화 없이 직접 통과합니다.")

        return args

    def _start_mitmdump_process(self, command: list) -> bool:
        """mitmdump 프로세스 시작 및 상태 확인"""
        mitm_log_file_path = self.app_dir / "mitm_debug.log"
        self.logger.info(f"mitmproxy 디버그 로그: {mitm_log_file_path}")

        try:
            # 환경 변수 설정
            env = os.environ.copy()
            python_path = env.get('PYTHONPATH', '')
            env['PYTHONPATH'] = f"{self.project_root}{os.pathsep}{python_path}"

            # 로그 파일 열기
            mitm_log_file = open(mitm_log_file_path, "w", encoding="utf-8")

            # Windows 콘솔 창 숨김
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

            # 프로세스 시작
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

            # 안정화 대기
            time.sleep(3)

            # 프로세스 상태 확인
            if self.process.poll() is None:
                self.is_running = True
                self.logger.info("프록시 서버가 성공적으로 시작되었습니다.")
                return True
            else:
                # 시작 실패
                mitm_log_file.close()
                with open(mitm_log_file_path, 'r', encoding='utf-8', errors='replace') as f:
                    error_content = f.read().strip()
                self.logger.warning(f"프록시 시작 실패 - 로그:\n{error_content[:500]}...")
                return False

        except FileNotFoundError:
            self.logger.error(f"mitmdump 실행 파일을 찾을 수 없습니다: {command[0]}")
            return False
        except Exception as e:
            self.logger.error(f"프록시 시작 중 예외 발생: {e}")
            if 'mitm_log_file' in locals() and not mitm_log_file.closed:
                mitm_log_file.close()
            return False
