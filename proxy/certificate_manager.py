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
from typing import Tuple
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateManager:
    """자체 CA 인증서 생성 및 시스템 설치 담당"""

    def __init__(self, mitm_dir: Path):
        self.mitm_dir = mitm_dir
        # Sentinel 자체 CA 인증서 파일명
        self.cert_path = mitm_dir / "sentinel-ca-cert.pem"
        self.ca_key_path = mitm_dir / "sentinel-ca-key.pem"
        self.logger = logging.getLogger(__name__)

        # 인증서 캐싱 (성능 최적화)
        self.cert_cache: dict = {}  # {hostname: (cert_pem, key_pem)}
        self.cert_cache_max: int = 100  # LRU 최대 캐시 크기

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

    def generate_server_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        특정 호스트를 위한 서버 인증서를 동적으로 생성 (Sentinel CA로 서명)
        캐싱을 통해 동일 호스트는 재생성하지 않음 (성능 최적화)

        Args:
            hostname: 대상 호스트 (예: chatgpt.com)

        Returns:
            (cert_pem, key_pem): 인증서와 키의 PEM 바이트
        """
        # 캐시 확인 (성능 최적화: RSA 키 생성 제거)
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        try:
            # 1. CA 인증서와 키 로드
            with open(self.cert_path, "rb") as f:
                ca_cert_pem = f.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

            with open(self.ca_key_path, "rb") as f:
                ca_key_pem = f.read()
                ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

            # 2. 서버용 개인 키 생성
            server_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # 3. 서버 인증서 속성 정의
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sentinel Interceptor"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])

            # 4. 서버 인증서 생성 (Sentinel CA로 서명)
            server_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject  # Sentinel CA가 발급자
            ).public_key(
                server_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            ).sign(ca_key, hashes.SHA256())  # CA 키로 서명

            # 5. PEM 형식으로 변환
            cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
            key_pem = server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # 6. 캐시에 저장 (LRU 방식)
            if len(self.cert_cache) >= self.cert_cache_max:
                # 가장 오래된 항목 제거 (FIFO - 간단한 LRU)
                oldest_key = next(iter(self.cert_cache))
                self.cert_cache.pop(oldest_key)
                self.logger.debug(f"인증서 캐시 가득참, 제거: {oldest_key}")

            self.cert_cache[hostname] = (cert_pem, key_pem)
            self.logger.info(f"서버 인증서 생성 및 캐싱 완료: {hostname} (캐시 크기: {len(self.cert_cache)}/{self.cert_cache_max})")

            return cert_pem, key_pem

        except Exception as e:
            self.logger.error(f"서버 인증서 생성 중 오류: {e}")
            raise