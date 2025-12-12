#!/usr/bin/env python3
"""
Base File Handler - 모든 LLM 파일 핸들러의 공통 기능
"""
from datetime import datetime
from typing import Dict, Any, Optional
from mitmproxy import http
import base64
import logging


class BaseFileHandler:
    """LLM 파일 핸들러 공통 베이스 클래스"""

    def __init__(self, server_client):
        """
        Args:
            server_client: 서버 통신 클라이언트
        """
        self.server_client = server_client

    def _detect_file_format(self, content: bytes) -> str:
        """파일 magic bytes로 포맷 감지"""
        # PDF
        if content.startswith(b'%PDF'):
            return "pdf"
        # PNG
        elif content.startswith(b'\x89PNG'):
            return "png"
        # JPEG
        elif content.startswith(b'\xff\xd8\xff'):
            return "jpg"
        # GIF
        elif content.startswith(b'GIF8'):
            return "gif"
        # ZIP/DOCX/XLSX
        elif content.startswith(b'PK\x03\x04'):
            return "docx"
        # Plain text (UTF-8 BOM)
        elif content.startswith(b'\xef\xbb\xbf'):
            return "txt"
        else:
            return "unknown"

    def _create_file_log_entry(
        self,
        public_ip: str,
        private_ip: str,
        host: str,
        hostname: str,
        file_name: str,
        attachment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """파일 로그 엔트리 생성"""
        return {
            "time": datetime.now().isoformat(),
            "public_ip": public_ip,
            "private_ip": private_ip,
            "host": host,
            "PCName": hostname,
            "prompt": f"[FILE: {file_name}]",
            "attachment": attachment,
            "interface": "llm"
        }

    def _send_file_to_server(
        self,
        file_log_entry: Dict[str, Any],
        service_name: str
    ) -> tuple:
        """서버로 파일 정보 전송 및 변조 정보 받기

        Returns:
            (file_change: bool, modified_file_data: str, modified_file_size: int)
        """
        logging.info(f"[{service_name}] 서버로 파일 정보 전송, 홀딩 시작...")
        file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, 0)
        logging.info(f"[{service_name}] 서버 응답 받음")

        response_attachment = file_decision.get("attachment", {})
        file_change = response_attachment.get("file_change", False)
        modified_file_data = response_attachment.get("data")
        modified_file_size = response_attachment.get("size")

        return file_change, modified_file_data, modified_file_size

    def _log_request_before_after(
        self,
        flow: http.HTTPFlow,
        service_name: str,
        original_length: int,
        modified_length: int
    ):
        """변조 전후 로깅"""
        logging.info(f"[{service_name}] ===== 원본 패킷 =====")
        logging.info(f"[{service_name}] 원본 URL: {flow.request.url}")
        logging.info(f"[{service_name}] 원본 Body Length: {original_length} bytes")
        logging.info(f"[{service_name}] ===== 변조된 패킷 =====")
        logging.info(f"[{service_name}] 변조된 URL: {flow.request.url}")
        logging.info(f"[{service_name}] 변조된 Body Length: {modified_length} bytes")

    def _safe_decode_file_data(
        self,
        attachment: Dict[str, Any],
        file_name: str,
        service_name: str,
        file_format: str = None
    ) -> Optional[bytes]:
        """base64 디코딩 및 로깅 (안전하게)

        Returns:
            bytes or None
        """
        try:
            file_data = base64.b64decode(attachment.get('data', ''))
            if file_format:
                logging.info(f"[{service_name}] 파일 업로드 감지: {file_name} ({len(file_data)} bytes, {file_format})")
            else:
                logging.info(f"[{service_name}] 파일 업로드 감지: {file_name} ({len(file_data)} bytes)")
            return file_data
        except:
            logging.info(f"[{service_name}] 파일 업로드 감지: {file_name}")
            return None

    def _set_request_content(self, flow: http.HTTPFlow, content: bytes):
        """Request content와 content-length 설정"""
        flow.request.set_content(content)
        flow.request.headers["content-length"] = str(len(content))
