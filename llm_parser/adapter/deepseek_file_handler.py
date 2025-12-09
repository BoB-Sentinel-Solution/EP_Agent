#!/usr/bin/env python3
"""
DeepSeek File Handler - DeepSeek 파일 업로드/변조 처리 전용 핸들러
단순 구조: POST 요청의 파일 바이너리만 변조
"""
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from mitmproxy import http
import base64
import json
import logging
import traceback


class DeepSeekFileHandler:
    """DeepSeek 파일 업로드/변조 처리 핸들러"""

    def __init__(
        self,
        server_client,
        cache_manager,
        log_manager,
        public_ip: str,
        private_ip: str,
        hostname: str
    ):
        """
        Args:
            server_client: 서버 통신 클라이언트
            cache_manager: 파일 캐시 매니저
            log_manager: 로그 매니저
            public_ip: 공인 IP
            private_ip: 사설 IP
            hostname: 호스트명
        """
        self.server_client = server_client
        self.cache_manager = cache_manager
        self.log_manager = log_manager
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.hostname = hostname


    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 업로드 POST 요청 감지 및 파일 데이터 추출

        Returns:
            {
                "attachment": {"format": str, "data": str, "file_name": str, "size": int},
                "file_name": str
            }
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # DeepSeek 업로드 호스트가 아니면 None
            if "chat.deepseek.com" not in host:
                return None

            # POST /api/v0/file/upload_file이 아니면 None
            if method != "POST" or "/api/v0/file/upload_file" not in path:
                return None

            logging.info(f"[DeepSeek] POST /api/v0/file/upload_file 감지")

            # Content-Type 확인
            content_type = flow.request.headers.get("content-type", "")

            if "multipart/form-data" in content_type:
                # multipart 파싱
                file_data, file_name = self._parse_multipart(flow.request.content, content_type)

                if not file_data:
                    logging.warning("[DeepSeek] multipart에서 파일 추출 실패")
                    return None

            else:
                # 순수 바이너리
                file_data = flow.request.content
                file_name = "upload.bin"

            if not file_data or len(file_data) < 100:
                logging.info("[DeepSeek] 파일 데이터가 너무 작음")
                return None

            # 파일 형식 추정 (magic bytes)
            file_format = self._detect_file_format(file_data)
            if file_name == "upload.bin" and file_format != "unknown":
                file_name = f"upload.{file_format}"

            # base64 인코딩
            encoded_data = base64.b64encode(file_data).decode('utf-8')

            logging.info(f"[DeepSeek] 파일 추출 성공: {file_name} ({len(file_data)} bytes, {file_format})")

            return {
                "attachment": {
                    "format": file_format,
                    "data": encoded_data,
                    "file_name": file_name,
                    "size": len(file_data)
                },
                "file_name": file_name
            }

        except Exception as e:
            logging.error(f"[DeepSeek] 파일 추출 중 오류: {e}")
            traceback.print_exc()
            return None


    def _parse_multipart(self, content: bytes, content_type: str) -> Tuple[Optional[bytes], str]:
        """multipart/form-data 파싱"""
        try:
            # boundary 추출
            boundary = None
            if "boundary=" in content_type:
                boundary = content_type.split("boundary=")[1].strip()
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]

            if not boundary:
                logging.warning("[DeepSeek] multipart boundary 없음")
                return None, "upload.bin"

            boundary_bytes = f"--{boundary}".encode()

            # 파일 데이터 찾기
            parts = content.split(boundary_bytes)

            for part in parts:
                if b'Content-Disposition' in part and b'filename=' in part:
                    # 파일명 추출
                    file_name = "upload.bin"
                    if b'filename="' in part:
                        start = part.find(b'filename="') + len(b'filename="')
                        end = part.find(b'"', start)
                        file_name = part[start:end].decode('utf-8', errors='ignore')

                    # 데이터 추출 (헤더와 데이터 사이 빈 줄로 구분)
                    if b'\r\n\r\n' in part:
                        data_start = part.find(b'\r\n\r\n') + 4
                        file_data = part[data_start:]
                        # 마지막 \r\n 제거
                        if file_data.endswith(b'\r\n'):
                            file_data = file_data[:-2]

                        logging.info(f"[DeepSeek] multipart 파일명: {file_name}, 크기: {len(file_data)}")
                        return file_data, file_name

            logging.warning("[DeepSeek] multipart에서 파일 파트를 찾지 못함")
            return None, "upload.bin"

        except Exception as e:
            logging.error(f"[DeepSeek] multipart 파싱 오류: {e}")
            traceback.print_exc()
            return None, "upload.bin"


    def _detect_file_format(self, content: bytes) -> str:
        """파일 magic bytes로 포맷 감지"""
        try:
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
                return "docx"  # DOCX로 추정
            # Plain text (UTF-8 BOM)
            elif content.startswith(b'\xef\xbb\xbf'):
                return "txt"
            else:
                return "unknown"
        except:
            return "unknown"


    def handle_file_upload(
        self,
        flow: http.HTTPFlow,
        host: str,
        public_ip: str,
        private_ip: str,
        hostname: str
    ) -> bool:
        """DeepSeek 파일 업로드 전체 처리

        1. 파일 추출 & 서버 통신
        2. 변조가 필요하면 현재 flow의 body 교체
        3. DeepSeek 서버가 변조된 파일 받아서 처리

        Returns:
            bool: 처리 완료 여부
        """
        try:
            # 파일 정보 추출
            upload_file_info = self.extract_file_from_upload_request(flow)
            if not upload_file_info:
                return False

            attachment = upload_file_info["attachment"]
            file_name = upload_file_info.get("file_name", "unknown")

            try:
                file_data = base64.b64decode(attachment.get('data', ''))
                logging.info(f"[DeepSeek POST] 파일 업로드 감지: {file_name} ({len(file_data)} bytes)")
            except:
                logging.info(f"[DeepSeek POST] 파일 업로드 감지: {file_name}")

            # 서버로 파일 정보 전송 → 변조 정보 받기
            file_log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": public_ip,
                "private_ip": private_ip,
                "host": host,
                "PCName": hostname,
                "prompt": f"[FILE: {file_name}]",
                "attachment": attachment,
                "interface": "llm"
            }

            logging.info(f"[DeepSeek] 서버로 파일 정보 전송, 홀딩 시작...")
            file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, 0)
            logging.info(f"[DeepSeek] 서버 응답 받음")

            # 서버 응답에서 변조 정보 가져오기
            response_attachment = file_decision.get("attachment", {})
            file_change = response_attachment.get("file_change", False)
            modified_file_data = response_attachment.get("data")

            if not file_change:
                logging.info(f"[DeepSeek] 파일 변조 안함")
                return True

            if not modified_file_data:
                logging.info(f"[DeepSeek] ⚠ 변조할 파일 데이터 없음")
                return True

            # ===== 파일 바이너리 변조 =====
            logging.info(f"[DeepSeek] 파일 변조 시작: {file_name}")

            # 현재 flow의 body 교체
            success = self.modify_binary_body(flow, modified_file_data, file_name)

            if success:
                logging.info(f"[DeepSeek] ✓ 파일 변조 완료")
            else:
                logging.info(f"[DeepSeek] ✗ 파일 변조 실패")

            return True

        except Exception as e:
            logging.error(f"[DeepSeek] 파일 업로드 처리 오류: {e}")
            traceback.print_exc()
            return False


    def modify_binary_body(self, flow: http.HTTPFlow, modified_file_data: str, file_name: str) -> bool:
        """현재 flow의 파일 바이너리 데이터 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_file_data: base64 인코딩된 변조할 파일 데이터
            file_name: 파일명

        Returns:
            bool: 변조 성공 여부
        """
        try:
            # base64 디코딩
            modified_bytes = base64.b64decode(modified_file_data)

            # Content-Type 확인
            content_type = flow.request.headers.get("content-type", "")

            # ===== 변조 전 로깅 =====
            logging.info(f"[DeepSeek POST] ===== 원본 POST 패킷 =====")
            logging.info(f"[DeepSeek POST] 원본 URL: {flow.request.url}")
            logging.info(f"[DeepSeek POST] 원본 Body Length: {len(flow.request.content)} bytes")

            if "multipart/form-data" in content_type:
                # multipart body 재구성
                boundary = None
                if "boundary=" in content_type:
                    boundary = content_type.split("boundary=")[1].strip()
                    if boundary.startswith('"') and boundary.endswith('"'):
                        boundary = boundary[1:-1]

                if boundary:
                    # multipart body 재구성
                    new_body = self._create_multipart_body(modified_bytes, file_name, boundary)
                    flow.request.set_content(new_body)
                    flow.request.headers["content-length"] = str(len(new_body))
                else:
                    # boundary 없으면 순수 바이너리로
                    flow.request.set_content(modified_bytes)
                    flow.request.headers["content-length"] = str(len(modified_bytes))
            else:
                # 순수 바이너리
                flow.request.set_content(modified_bytes)
                flow.request.headers["content-length"] = str(len(modified_bytes))

            # ===== 변조 후 로깅 =====
            logging.info(f"[DeepSeek POST] ===== 변조된 POST 패킷 =====")
            logging.info(f"[DeepSeek POST] 변조된 URL: {flow.request.url}")
            logging.info(f"[DeepSeek POST] 변조된 Body Length: {len(flow.request.content)} bytes")

            logging.info(f"[DeepSeek] 파일 데이터 변조 완료")
            return True

        except Exception as e:
            logging.error(f"[DeepSeek] 파일 변조 실패: {e}")
            traceback.print_exc()
            return False


    def _create_multipart_body(self, file_data: bytes, file_name: str, boundary: str) -> bytes:
        """multipart/form-data body 재구성"""
        body = b''
        body += f'--{boundary}\r\n'.encode()
        body += f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'.encode()
        body += b'Content-Type: application/octet-stream\r\n'
        body += b'\r\n'
        body += file_data
        body += b'\r\n'
        body += f'--{boundary}--\r\n'.encode()
        return body
