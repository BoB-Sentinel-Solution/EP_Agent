#!/usr/bin/env python3
"""
MCP 설정 디버깅 출력 - JSON 형식
dispatcher의 IP 수집 코드 재사용
"""

import json
import socket
import platform
import requests
from typing import Dict, Any
from datetime import datetime


def get_public_ip() -> str:
    """공인 IP 조회 (dispatcher와 동일)"""
    try:
        session = requests.Session()
        session.trust_env = False
        session.proxies = {}

        response = session.get('https://api.ipify.org?format=json', timeout=3, verify=False)
        if response.status_code == 200:
            return response.json().get('ip', 'unknown')
        return 'unknown'
    except Exception as e:
        print(f"[WARN] 공인 IP 조회 실패: {e}")
        return 'unknown'


def get_private_ip() -> str:
    """사설 IP 조회 (dispatcher와 동일)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return 'unknown'


def print_mcp_json(service: str, file_path: str, raw_content: str, status: str = "activate"):
    """
    MCP 설정을 JSON 형식으로 출력 (파일 내용 그대로)

    Args:
        service: 서비스 이름 (claude, vscode, cursor)
        file_path: 파일 경로
        raw_content: 파일 내용 (raw string)
        status: 상태 (activate/delete)
    """
    output = {
        "pc_name": platform.node(),
        "public_ip": get_public_ip(),
        "private_ip": get_private_ip(),
        "hostname": socket.gethostname(),
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "file_path": file_path,
        "config_raw": raw_content  # 파일 내용 그대로
    }

    print("\n" + "="*80)
    print(json.dumps(output, indent=2, ensure_ascii=False))
    print("="*80 + "\n")
