#!/usr/bin/env python3
"""
MCP 설정 디버깅 출력 - JSON 형식
dispatcher의 IP 수집 함수 재사용
"""

import json
import socket
import platform
import sys
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

# dispatcher의 IP 조회 함수 import
sys.path.insert(0, str(Path(__file__).parent.parent))
from proxy_dispatcher.dispatcher import UnifiedDispatcher
from utils.network_utils import get_public_ip, get_private_ip


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
            "time": datetime.now().isoformat(),
            "public_ip": get_public_ip(),
            "private_ip": get_private_ip(),
            "host": service,
            "PCName": platform.node(),
            "status": status,
            "file_path": file_path,
            "config_raw": raw_content 
    }

    print("\n" + "="*80)
    print(json.dumps(output, indent=2, ensure_ascii=False))
    print("="*80 + "\n")
