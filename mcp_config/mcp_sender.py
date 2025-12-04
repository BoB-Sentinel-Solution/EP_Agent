#!/usr/bin/env python3
"""
MCP 설정 서버 전송 모듈
- 추출한 MCP 설정을 서버로 전송
"""
import platform
import requests
import logging
import json
from pathlib import Path
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
            logger.info(f"[MCP 전송] 서버: {self.server_url}")
            logger.info(f"[MCP 전송] 서비스: {service}")
            logger.info(f"[MCP 전송] 상태: {status}")
            logger.info(f"[MCP 전송] 파일 경로: {file_path}")

            # config_raw를 JSON 객체로 파싱 (필수)
            try:
                config_parsed = json.loads(raw_content)
            except Exception as e:
                logger.error(f"[MCP 전송] JSON 파싱 실패: {e}")
                logger.error(f"[MCP 전송] 파일이 올바른 JSON 형식이 아닙니다. 전송을 중단합니다.")
                return False

            # 세션 생성 (프록시 환경변수 무시)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # 전송할 데이터 구성
            payload = {
                "time": datetime.now().isoformat(),
                "public_ip": get_public_ip(),
                "private_ip": get_private_ip(),
                "host": service,
                "PCName": platform.node(),
                "status": status,
                "file_path": file_path,
                "config_raw": config_parsed  # JSON 객체만 전송
            }

            logger.info(f"[MCP 전송] 페이로드 크기: {len(str(payload))} bytes")
            logger.info(f"[MCP 전송] Public IP: {payload['public_ip']}")
            logger.info(f"[MCP 전송] Private IP: {payload['private_ip']}")
            logger.info(f"[MCP 전송] PC Name: {payload['PCName']}")
            logger.info(f"[MCP 전송] Config 크기: {len(raw_content)} bytes")

            # mitm_debug.log에 요청 데이터 기록 (서버로 보내는 payload 그대로)
            mitm_debug_log = Path.home() / ".llm_proxy" / "mitm_debug.log"
            try:
                with open(mitm_debug_log, "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"[MCP 서버 전송 요청] {datetime.now().isoformat()}\n")
                    f.write(f"{'='*80}\n")
                    f.write(json.dumps(payload, indent=2, ensure_ascii=False))
                    f.write(f"\n{'='*80}\n\n")
            except Exception as e:
                logger.warning(f"mitm_debug.log 쓰기 실패: {e}")

            # 요청 전송
            logger.info(f"[MCP 전송] POST 요청 시작...")
            response = session.post(
                self.server_url,
                json=payload,
                timeout=(self.connect_timeout, self.read_timeout),
                verify=self.verify_tls
            )

            # 응답 처리
            logger.info(f"[MCP 전송] 응답 상태 코드: {response.status_code}")

            # mitm_debug.log에 응답 데이터 기록
            try:
                with open(mitm_debug_log, "a", encoding="utf-8") as f:
                    f.write(f"[MCP 서버 응답] {datetime.now().isoformat()}\n")
                    f.write(f"상태 코드: {response.status_code}\n")
                    f.write(f"{'-'*80}\n")
                    if response.status_code == 200:
                        try:
                            response_data = response.json()
                            f.write(json.dumps(response_data, indent=2, ensure_ascii=False))
                        except:
                            f.write(response.text)
                    else:
                        f.write(response.text)
                    f.write(f"\n{'='*80}\n\n")
            except Exception as e:
                logger.warning(f"mitm_debug.log 쓰기 실패: {e}")

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    logger.info(f"[MCP 전송] ✓ 전송 성공 - 응답: {response_data}")
                except:
                    logger.info(f"[MCP 전송] ✓ 전송 성공 - 응답: {response.text[:200]}")
                return True
            else:
                logger.error(f"[MCP 전송] ✗ 서버 오류: HTTP {response.status_code}")
                logger.error(f"[MCP 전송] 응답 본문: {response.text[:500]}")
                return False

        except requests.exceptions.ProxyError as e:
            logger.error(f"[MCP 전송] [PROXY] 프록시 오류: {e}")
            return False
        except requests.exceptions.SSLError as e:
            logger.error(f"[MCP 전송] [TLS] 인증서 오류: {e}")
            return False
        except requests.exceptions.ConnectTimeout:
            logger.error(f"[MCP 전송] [NET] 연결 타임아웃 (서버: {self.server_url})")
            return False
        except requests.exceptions.ReadTimeout:
            logger.error(f"[MCP 전송] [NET] 읽기 타임아웃")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"[MCP 전송] [NET] 요청 실패: {repr(e)}")
            return False
        except Exception as e:
            logger.error(f"[MCP 전송] 예상치 못한 오류: {e}")
            import traceback
            logger.error(f"[MCP 전송] 스택 트레이스:\n{traceback.format_exc()}")
            return False



