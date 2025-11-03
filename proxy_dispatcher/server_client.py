#!/usr/bin/env python3
"""
서버 통신 클라이언트 - 제어 결정 요청
"""
import requests
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from mitmproxy import ctx

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


class ServerClient:
    """Sentinel 서버와 통신하는 클라이언트"""

    def __init__(self, server_url: str, verify_tls: bool = False):
        """
        Args:
            server_url: 서버 URL (예: https://158.180.72.194/logs)
            verify_tls: TLS 인증서 검증 여부
        """
        self.server_url = server_url
        self.verify_tls = verify_tls
        self.connect_timeout = 3.0
        self.read_timeout = 12.0

    def get_control_decision(self, log_entry: Dict[str, Any], parse_time: float) -> Tuple[Dict[str, Any], Optional[datetime], Optional[datetime]]:
        """
        서버로 제어 결정을 요청

        Args:
            log_entry: 로그 엔트리 (프롬프트, 호스트 등)
            parse_time: 파싱 시간

        Returns:
            (decision, step2_timestamp, step3_timestamp)
            - decision: {"action": "allow", "modified_prompt": "..."} 형태
            - step2_timestamp: 서버 요청 시점
            - step3_timestamp: 서버 응답 시점
        """
        try:
            info(f"서버에 요청 중... ({log_entry['host']}) -> {self.server_url}")

            # 세션 생성 (프록시 환경변수 무시)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # 요청 전송
            step2_timestamp = datetime.now()
            response = session.post(
                self.server_url,
                json=log_entry,
                timeout=(self.connect_timeout, self.read_timeout),
                verify=self.verify_tls
            )
            step3_timestamp = datetime.now()

            # 응답 처리
            if response.status_code == 200:
                decision = response.json()
                info(f"서버 응답: {decision}")
                return (decision, step2_timestamp, step3_timestamp)
            else:
                info(f"서버 오류: HTTP {response.status_code} {response.text[:200]}")
                return ({'action': 'allow'}, step2_timestamp, step3_timestamp)

        except requests.exceptions.ProxyError as e:
            info(f"[PROXY] 프록시 오류: {e}")
            return ({'action': 'allow'}, None, None)
        except requests.exceptions.SSLError as e:
            info(f"[TLS] 인증서 오류: {e}")
            return ({'action': 'allow'}, None, None)
        except requests.exceptions.ConnectTimeout:
            info("[NET] 연결 타임아웃")
            return ({'action': 'allow'}, None, None)
        except requests.exceptions.ReadTimeout:
            info("[NET] 읽기 타임아웃")
            return ({'action': 'allow'}, None, None)
        except requests.exceptions.RequestException as e:
            info(f"[NET] 요청 실패: {repr(e)}")
            return ({'action': 'allow'}, None, None)
