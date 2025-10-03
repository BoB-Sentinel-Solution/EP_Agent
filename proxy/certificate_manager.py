#!/usr/bin/env python3
"""
인증서 관리자 - mitmproxy CA 인증서 생성 및 설치
"""

import os
import sys
import logging
import subprocess
from pathlib import Path
from locale import getpreferredencoding


class CertificateManager:
    """mitmproxy CA 인증서 생성 및 시스템 설치 담당"""

    def __init__(self, mitm_dir: Path):
        self.mitm_dir = mitm_dir
        self.cert_path = mitm_dir / "mitmproxy-ca-cert.pem"
        self.logger = logging.getLogger(__name__)

    def install_certificate(self):
        """mitmproxy CA 인증서를 생성하고 Windows에 설치"""
        if os.name != 'nt':
            self.logger.info("인증서 자동 설치는 Windows에서만 지원됩니다.")
            return

        self.mitm_dir.mkdir(exist_ok=True)

        # 인증서 생성
        if not self.cert_path.exists():
            self._generate_certificate()

        # 인증서 설치
        if self.cert_path.exists():
            self._install_to_windows_store()
        else:
            self.logger.error("인증서 파일이 없어 설치를 건너뜁니다.")

    def _generate_certificate(self):
        """인증서 파일 생성"""
        self.logger.info("mitmproxy 인증서 파일을 생성합니다...")

        # 시도 1: Python 모듈로 실행
        cmd_list = [sys.executable, '-m', 'mitmproxy.tools.mitmdump', '--set', f'confdir={self.mitm_dir}']
        try:
            subprocess.run(cmd_list, timeout=10, capture_output=True,
                         encoding=getpreferredencoding(), errors='ignore')
        except subprocess.TimeoutExpired:
            pass  # 타임아웃은 정상 (백그라운드에서 인증서 생성 완료)
        except Exception as e:
            self.logger.warning(f"Python 모듈 방식의 인증서 생성 중 오류 발생: {e}")

        # 시도 2: 직접 실행 파일로 실행 (시도 1 실패 시)
        if not self.cert_path.exists():
            self.logger.info("모듈 실행 방식 실패. 직접 실행 방식으로 다시 시도합니다...")
            mitmdump_exe = self._find_mitmdump_executable()
            if mitmdump_exe:
                try:
                    subprocess.run([mitmdump_exe, '--set', f'confdir={self.mitm_dir}'], timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                except Exception as e:
                    self.logger.error(f"직접 실행 방식의 인증서 생성 중 오류 발생: {e}")
            else:
                self.logger.error("mitmdump.exe를 찾을 수 없어 인증서를 생성할 수 없습니다.")

        # 최종 확인
        if not self.cert_path.exists():
            self.logger.error("모든 방법으로 인증서 파일 생성에 실패했습니다.")

    def _install_to_windows_store(self):
        """Windows 인증서 저장소에 설치"""
        self.logger.info("Windows 인증서 저장소에 mitmproxy CA를 설치합니다...")

        try:
            # 이미 설치되어 있는지 확인
            check_cmd = ['certutil', '-user', '-verifystore', 'Root', 'mitmproxy']
            result = subprocess.run(check_cmd, capture_output=True, text=True, encoding=getpreferredencoding())
            if "mitmproxy" in result.stdout and "찾을" not in result.stdout:
                self.logger.info("인증서가 이미 설치되어 있습니다.")
                return

            # 설치 실행
            add_cmd = ['certutil', '-user', '-addstore', 'Root', str(self.cert_path)]
            subprocess.run(add_cmd, check=True, capture_output=True, text=True, encoding=getpreferredencoding())
            self.logger.info("인증서 설치 성공! 이제 HTTPS 트래픽을 감지할 수 있습니다.")

        except FileNotFoundError:
            self.logger.error("'certutil' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"certutil 명령어 실행 실패! (관리자 권한으로 실행했는지 확인하세요)")
            self.logger.error(f"오류 내용: {e.stderr}")

    def _find_mitmdump_executable(self) -> str:
        """mitmdump 실행 파일 경로 찾기 (간단 버전)"""
        if os.name == 'nt':
            scripts_dir = Path(sys.executable).parent / "Scripts"
            mitmdump_path = scripts_dir / "mitmdump.exe"
            if mitmdump_path.exists():
                return str(mitmdump_path)
        return None
