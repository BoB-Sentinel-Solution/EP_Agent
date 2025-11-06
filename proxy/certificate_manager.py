#!/usr/bin/env python3
"""
인증서 관리자 - 자체 CA 인증서 생성 및 설치 (Sentinel 적용)
"""

import os
import sys
import logging
import subprocess
from pathlib import Path
from locale import getpreferredencoding
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateManager:
    """자체 CA 인증서 생성 및 시스템 설치 담당"""

    def __init__(self, mitm_dir: Path):
        self.mitm_dir = mitm_dir
        # CA 인증서 경로 이름 수정
        self.cert_path = mitm_dir / "sentinel-ca-cert.pem" 
        # CA 개인 키 경로 이름 수정
        self.ca_key_path = mitm_dir / "sentinel-ca.key" 
        self.logger = logging.getLogger(__name__)

    def install_certificate(self):
        """CA 인증서를 생성하고 Windows에 설치"""
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
        """CA 인증서 파일 생성 (Common Name: Sentinel)"""
        self.logger.info("자체 CA 개인 키와 인증서를 생성합니다...")

        try:
            # 1. 개인 키 생성
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            with open(self.ca_key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # 2. CA 인증서 속성 정의 (Sentinel 적용)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sentinel Interceptor"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel"), 
            ])
            
            # 3. 인증서 생성 및 서명
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(key, hashes.SHA256())
            
            # 4. PEM 파일로 저장 (설치에 필요한 파일)
            with open(self.cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.logger.info(f"CA 인증서 파일 생성 성공: {self.cert_path.name}")

        except Exception as e:
            self.logger.error(f"CA 인증서 자체 생성 중 오류 발생: {e}")
            self.logger.error("cryptography 라이브러리가 설치되어 있는지 확인하세요.")


    def _install_to_windows_store(self):
        """Windows 인증서 저장소에 설치"""
        self.logger.info("Windows 인증서 저장소에 Sentinel CA를 설치합니다...")

        try:
            # 이미 설치되어 있는지 확인 (Common Name: Sentinel)
            check_cmd = ['certutil', '-user', '-verifystore', 'Root', 'Sentinel'] 
            result = subprocess.run(check_cmd, capture_output=True, text=True, encoding=getpreferredencoding())
            if "Sentinel" in result.stdout and "찾을" not in result.stdout:
                self.logger.info("Sentinel CA 인증서가 이미 설치되어 있습니다.")
                return

            # 설치 실행
            add_cmd = ['certutil', '-user', '-addstore', 'Root', str(self.cert_path)]
            subprocess.run(add_cmd, check=True, capture_output=True, text=True, encoding=getpreferredencoding())
            self.logger.info("Sentinel CA 인증서 설치 성공! 이제 프록시를 통해 HTTPS 트래픽을 처리할 수 있습니다.")

        except FileNotFoundError:
            self.logger.error("'certutil' 명령을 찾을 수 없습니다. Windows 환경이 맞는지 확인하세요.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"certutil 명령어 실행 실패! (관리자 권한으로 실행했는지 확인하세요)")
            self.logger.error(f"오류 내용: {e.stderr}")

    def _find_mitmdump_executable(self) -> str:
        """mitmdump 실행 파일 찾기 로직 제거"""
        return None