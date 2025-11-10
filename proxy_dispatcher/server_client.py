#!/usr/bin/env python3
"""
서버 통신 클라이언트 - 제어 결정 요청
"""
import os
import requests
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from mitmproxy import ctx
import urllib3

# urllib3 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def __init__(self, server_url: str, verify_tls: bool = False, proxy_port: int = None):
        self.server_url = server_url
        self.verify_tls = verify_tls
        self.connect_timeout = 3.0
        self.read_timeout = 12.0

        # 프록시 포트가 제공되면 프록시 사용
        if proxy_port:
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            self._proxy_config = {
                'http': proxy_url,
                'https': proxy_url
            }
            info(f"[PROXY] Sentinel 프록시 사용: {proxy_url}")
        else:
            self._proxy_config = None
            info(f"[PROXY] 프록시 미사용 (직접 연결)")

    def get_control_decision(self, log_entry: Dict[str, Any], parse_time: float) -> Tuple[Dict[str, Any], Optional[datetime], Optional[datetime]]:
        """
        서버로 제어 결정을 요청

        Note: bobsentinel.site는 proxy_server.py에서 투명 터널링되므로
              시스템 프록시를 통해 proxy_server.py로 요청 → 투명 터널링 → 서버
        """
        try:
            info(f"서버에 요청 중... ({log_entry['host']}) -> {self.server_url}")

            # 시스템 프록시를 통해 요청 (투명 터널링됨)
            step2_timestamp = datetime.now()
            response = requests.post(
                self.server_url,
                json=log_entry,
                timeout=(self.connect_timeout, self.read_timeout),
                verify=self.verify_tls,
                proxies=self._proxy_config  # 시스템 프록시 사용
            )
            step3_timestamp = datetime.now()
            info(f"[DEBUG] 서버 응답 수신 완료 - 상태: {response.status_code}")
        
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
