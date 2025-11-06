#!/usr/bin/env python3
"""
MCP 설정 서버 전송 모듈
- 추출한 MCP 설정을 서버로 전송
"""
import platform
import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# 공통 네트워크 유틸리티 import
from utils.network_utils import get_public_ip, get_private_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MCPConfigSender:
    """MCP 설정을 서버로 전송하는 클래스"""

    def __init__(self, server_url: str, verify_tls: bool = False):
        """
        Args:
            server_url: 서버 URL (예: https://158.180.72.194/mcp-configs)
            verify_tls: TLS 인증서 검증 여부
        """
        self.server_url = server_url
        self.verify_tls = verify_tls
        self.connect_timeout = 5.0
        self.read_timeout = 15.0

    def send_config(self, service: str, file_path: str, raw_content: str, status: str = "activate") -> bool:
        """
        MCP 설정을 서버로 전송 (mcp_debugger와 동일한 양식)

        Args:
            service: 서비스 이름 (claude, vscode, cursor)
            file_path: 파일 경로
            raw_content: 파일 내용 (raw string)
            status: 상태 (activate/delete)

        Returns:
            성공 여부 (True/False)
        """
        try:
            logger.info(f"서버로 MCP 설정 전송 중... -> {self.server_url}")

            # 세션 생성 (프록시 환경변수 무시)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # mcp_debugger와 동일한 양식
            payload = {
                "time": datetime.now().isoformat(),
                "public_ip": get_public_ip(),
                "private_ip": get_private_ip(),
                "host": service,
                "PCName": platform.node(),
                "status": status,
                "file_path": file_path,
                "config_raw": raw_content
            }

            # 요청 전송
            response = session.post(
                self.server_url,
                json=payload,
                timeout=(self.connect_timeout, self.read_timeout),
                verify=self.verify_tls
            )

            # 응답 처리
            if response.status_code == 200:
                logger.info(f"✓ 서버 전송 성공: {response.json()}")
                return True
            else:
                logger.error(f"✗ 서버 오류: HTTP {response.status_code} {response.text[:200]}")
                return False

        except requests.exceptions.ProxyError as e:
            logger.error(f"[PROXY] 프록시 오류: {e}")
            return False
        except requests.exceptions.SSLError as e:
            logger.error(f"[TLS] 인증서 오류: {e}")
            return False
        except requests.exceptions.ConnectTimeout:
            logger.error("[NET] 연결 타임아웃")
            return False
        except requests.exceptions.ReadTimeout:
            logger.error("[NET] 읽기 타임아웃")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"[NET] 요청 실패: {repr(e)}")
            return False
        except Exception as e:
            logger.error(f"예상치 못한 오류: {e}")
            return False

    def send_configs_individually(self, configs: Dict[str, Any]) -> Dict[str, bool]:
        """
        각 서비스의 설정을 개별적으로 전송

        Args:
            configs: 서비스별 MCP 설정 딕셔너리

        Returns:
            서비스별 전송 결과 (service_name -> success)
        """
        results = {}

        for service_name, config in configs.items():
            logger.info(f"--- {service_name.upper()} 설정 전송 시작 ---")
            success = self.send_config({service_name: config})
            results[service_name] = success

        return results


class MCPConfigSenderMock:
    """테스트용 Mock 전송 클래스"""

    def __init__(self, server_url: str = "http://localhost:8000/mcp-configs", verify_tls: bool = False):
        self.server_url = server_url
        self.verify_tls = verify_tls
        logger.info(f"[MOCK MODE] 서버 전송 시뮬레이션 모드 (URL: {server_url})")

    def send_config(self, config_data: Dict[str, Any]) -> bool:
        """Mock 전송 - 실제로는 서버에 보내지 않음"""
        logger.info(f"[MOCK] 서버로 데이터 전송 시뮬레이션...")
        logger.info(f"[MOCK] 전송 데이터 크기: {len(str(config_data))} bytes")

        # 전송할 데이터 구조 출력
        for service, config in config_data.items():
            if isinstance(config, dict):
                mcp_servers = config.get("mcp_servers", {})
                if isinstance(mcp_servers, dict):
                    logger.info(f"[MOCK] {service}: {len(mcp_servers)}개 MCP 서버")

        logger.info(f"[MOCK] ✓ 전송 성공 (시뮬레이션)")
        return True

    def send_configs_individually(self, configs: Dict[str, Any]) -> Dict[str, bool]:
        """Mock 개별 전송"""
        results = {}
        for service_name, config in configs.items():
            logger.info(f"[MOCK] --- {service_name.upper()} 설정 전송 시뮬레이션 ---")
            results[service_name] = self.send_config({service_name: config})
        return results


