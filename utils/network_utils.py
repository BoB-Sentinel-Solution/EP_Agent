#!/usr/bin/env python3
"""
네트워크 유틸리티 - IP 조회 함수
dispatcher와 mcp_config에서 공통 사용
"""

import socket
import requests


def get_public_ip() -> str:
    """공인 IP 조회"""
    try:
        session = requests.Session()
        session.trust_env = False
        session.proxies = {}

        response = session.get('https://api.ipify.org?format=json', timeout=3, verify=False)
        if response.status_code == 200:
            return response.json().get('ip', 'unknown')
        return 'unknown'
    except Exception:
        return 'unknown'


def get_private_ip() -> str:
    """사설 IP 조회"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return 'unknown'
