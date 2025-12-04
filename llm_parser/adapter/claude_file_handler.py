#!/usr/bin/env python3
"""
Claude File Handler - Claude 파일 업로드/변조 처리 전용 핸들러
claude.py에서 분리
"""
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from mitmproxy import http, ctx
import base64
import json
import logging
import traceback
import re
from llm_parser.common.utils import FileUtils

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


class ClaudeFileHandler:
    """Claude 파일 업로드/변조 처리 핸들러"""

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


    # ===== 파일 등록/업로드 핵심 메소드 =====

    def handle_file_upload(
        self,
        flow: http.HTTPFlow,
        host: str,
        public_ip: str,
        private_ip: str,
        hostname: str
    ) -> bool:
        """Claude 파일 업로드 전체 처리 (POST /upload 요청)

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
            file_format = attachment.get("format", "unknown")

            try:
                file_data = base64.b64decode(attachment.get('data', ''))
                logging.info(f"[Claude POST] 파일 업로드 감지: {file_name} ({len(file_data)} bytes, {file_format})")
            except:
                logging.info(f"[Claude POST] 파일 업로드 감지: {file_name}")

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

            logging.info(f"[Claude] 서버로 파일 정보 전송, 홀딩 시작...")
            file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, 0)
            logging.info(f"[Claude] 서버 응답 받음")

            # 서버 응답에서 변조 정보 가져오기
            response_attachment = file_decision.get("attachment", {})
            file_change = response_attachment.get("file_change", False)
            modified_file_data = response_attachment.get("data")
            modified_file_size = response_attachment.get("size")

            if not file_change:
                logging.info(f"[Claude] 파일 변조 안함")
                return True

            if not modified_file_data:
                logging.info(f"[Claude] ⚠ 변조할 파일 데이터 없음")
                return True

            # 모든 파일 타입에 대해 multipart body 직접 교체 (Cloudflare 우회)
            logging.info(f"[Claude] 파일 변조 시작: {file_format} ({modified_file_size} bytes)")
            success = self.modify_multipart_file_data(flow, modified_file_data)

            if success:
                logging.info(f"[Claude] ✓ 파일 변조 완료")
            else:
                logging.info(f"[Claude] ✗ 파일 변조 실패")

            return True

        except Exception as e:
            logging.error(f"[Claude] 파일 업로드 처리 오류: {e}")
            traceback.print_exc()
            return False


    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 업로드 POST 요청 감지 및 파일 데이터 추출

        Returns:
            {
                "attachment": {"format": str, "data": str},
                "file_name": str,
                "timestamp": int
            }
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # Claude 관련 호스트가 아니면 None
            if "claude.ai" not in host:
                return None

            # POST /upload 또는 /convert_document가 아니면 None
            if method != "POST" or not ("/upload" in path or "/convert_document" in path):
                return None

            content_type = flow.request.headers.get("content-type", "").lower()

            # multipart/form-data가 아니면 None
            if "multipart/form-data" not in content_type:
                return None

            # 경로 확인 로깅
            if "/upload" in path:
                logging.info(f"[Claude] POST /upload 감지")
            elif "/convert_document" in path:
                logging.info(f"[Claude] POST /convert_document 감지 (문서 파일)")

            # boundary 추출
            boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
            if not boundary_match:
                logging.error("[Claude] multipart boundary를 찾을 수 없습니다")
                return None

            boundary = boundary_match.group(1)

            # 스트리밍 업로드 처리
            try:
                content = flow.request.get_content()
            except:
                content = flow.request.content

            if not content or len(content) < 100:
                return None

            # multipart 파싱: 파일 데이터 추출
            file_data, file_name, file_format = self._parse_multipart(content, boundary)

            if not file_data:
                logging.error("[Claude] multipart 파일 데이터 추출 실패")
                return None

            # base64 인코딩
            encoded_data = base64.b64encode(file_data).decode('utf-8')

            logging.info(f"[Claude] 파일 추출 성공: {file_name} ({len(file_data)} bytes, {file_format})")

            # timestamp 생성 (매칭용)
            import time
            timestamp = int(time.time() * 1000)

            return {
                "attachment": {
                    "format": file_format,
                    "data": encoded_data
                },
                "file_name": file_name,
                "timestamp": timestamp
            }

        except Exception as e:
            logging.error(f"[Claude] 파일 추출 중 오류: {e}")
            traceback.print_exc()
            return None


    def _parse_multipart(self, content: bytes, boundary: str) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """multipart/form-data 파싱하여 파일 데이터, 파일명, 포맷 추출"""
        try:
            # boundary로 구분
            parts = content.split(f'--{boundary}'.encode())

            for part in parts:
                if b'Content-Disposition' not in part:
                    continue

                # Content-Disposition 헤더에서 파일명 추출
                disposition_match = re.search(rb'Content-Disposition:.*filename="([^"]+)"', part)
                if not disposition_match:
                    # filename*= 형식도 확인
                    disposition_match = re.search(rb'Content-Disposition:.*filename\*=.*\'\'([^\r\n;]+)', part)
                    if not disposition_match:
                        continue

                file_name = disposition_match.group(1).decode('utf-8', errors='ignore')

                # Content-Type 추출
                content_type_match = re.search(rb'Content-Type:\s*([^\r\n]+)', part)
                file_format = "unknown"
                if content_type_match:
                    content_type_value = content_type_match.group(1).decode('utf-8', errors='ignore').strip()
                    file_format = FileUtils.extract_format_from_content_type(content_type_value)

                # 헤더와 바디 구분 (\r\n\r\n)
                header_body_split = part.split(b'\r\n\r\n', 1)
                if len(header_body_split) < 2:
                    continue

                file_data = header_body_split[1]

                # 끝부분 정리 (마지막 \r\n 제거)
                file_data = file_data.rstrip(b'\r\n')

                return file_data, file_name, file_format

            return None, None, None

        except Exception as e:
            logging.error(f"[Claude] multipart 파싱 실패: {e}")
            return None, None, None


    def modify_multipart_file_data(self, flow: http.HTTPFlow, modified_file_data: str) -> bool:
        """multipart body에서 파일 데이터만 교체 (이미지 전용)

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_file_data: base64 인코딩된 변조할 파일 데이터

        Returns:
            bool: 변조 성공 여부
        """
        try:
            # base64 디코딩
            modified_bytes = base64.b64decode(modified_file_data)

            content_type = flow.request.headers.get("content-type", "")
            boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
            if not boundary_match:
                return False

            boundary = boundary_match.group(1)
            original_content = flow.request.content

            # multipart를 파싱해서 파일 부분만 교체
            parts = original_content.split(f'--{boundary}'.encode())
            new_parts = []

            for part in parts:
                if b'Content-Disposition' in part and b'filename=' in part:
                    # 파일 파트 발견 - 헤더는 유지하고 데이터만 교체
                    header_body_split = part.split(b'\r\n\r\n', 1)
                    if len(header_body_split) == 2:
                        header = header_body_split[0]
                        # 새 파일 데이터로 교체
                        new_part = header + b'\r\n\r\n' + modified_bytes + b'\r\n'
                        new_parts.append(new_part)
                        logging.info(f"[Claude] 파일 부분 교체: {len(modified_bytes)} bytes")
                    else:
                        new_parts.append(part)
                else:
                    new_parts.append(part)

            # 새로운 multipart body 생성
            new_content = (f'--{boundary}'.encode()).join(new_parts)

            # ===== 변조 전 로깅 =====
            logging.info(f"[Claude POST] ===== 원본 POST 패킷 =====")
            logging.info(f"[Claude POST] 원본 URL: {flow.request.url}")
            logging.info(f"[Claude POST] 원본 Body Length: {len(original_content)} bytes")

            # body 교체
            flow.request.set_content(new_content)
            flow.request.headers["content-length"] = str(len(new_content))

            # ===== 변조 후 로깅 =====
            logging.info(f"[Claude POST] ===== 변조된 POST 패킷 =====")
            logging.info(f"[Claude POST] 변조된 URL: {flow.request.url}")
            logging.info(f"[Claude POST] 변조된 Body Length: {len(new_content)} bytes")

            logging.info(f"[Claude] multipart 파일 데이터 변조 완료")
            return True

        except Exception as e:
            logging.error(f"[Claude] multipart 변조 실패: {e}")
            traceback.print_exc()
            return False


    def extract_file_uuid_from_response(self, flow: http.HTTPFlow) -> Optional[str]:
        """Claude 업로드 응답에서 file_uuid 추출

        응답 형식:
        {
            "success": true,
            "file_uuid": "f07ca4d1-05c3-4e1c-b516-931925b18971",
            "file_name": "1764769232907_image.png",
            "size_bytes": 20466,
            ...
        }
        """
        try:
            if not flow.response:
                return None

            content_type = flow.response.headers.get("content-type", "").lower()
            if "application/json" not in content_type:
                return None

            response_body = flow.response.content.decode('utf-8', errors='replace')
            response_data = json.loads(response_body)

            file_uuid = response_data.get("file_uuid")
            if file_uuid:
                logging.info(f"[Claude] 응답에서 file_uuid 추출: {file_uuid}")
                return file_uuid

            return None

        except Exception as e:
            logging.error(f"[Claude] 응답 파싱 오류: {e}")
            return None


    # ===== completion 요청에서 file_uuid 교체 =====

    def modify_completion_files(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """Claude completion 요청에서 files[] 배열의 uuid 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            body_str = flow.request.content.decode('utf-8')
            body_data = json.loads(body_str)

            files = body_data.get('files', [])
            if not files:
                return False

            logging.info(f"[Claude Completion] 요청 감지, files: {files}")

            modified = False
            new_files = []

            for original_uuid in files:
                # 캐시에서 매핑 조회
                new_uuid = cache_manager.get_new_file_id(original_uuid)

                if new_uuid:
                    logging.info(f"[Claude Completion] ✓ uuid 교체: {original_uuid} → {new_uuid}")
                    new_files.append(new_uuid)
                    modified = True
                else:
                    # 매핑 없으면 원본 사용
                    new_files.append(original_uuid)

            if modified:
                # files 배열 교체
                body_data['files'] = new_files
                new_body_str = json.dumps(body_data)

                # 요청 body 변조
                flow.request.content = new_body_str.encode('utf-8')
                flow.request.headers['content-length'] = str(len(new_body_str))

                logging.info(f"[Claude Completion] ✓ files 배열 교체 완료")
                return True

        except Exception as e:
            logging.error(f"[Claude Completion] 처리 오류: {e}")
            traceback.print_exc()

        return False


    # ===== 통합 Claude 요청 처리 =====

    def process_claude_specific_requests(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """Claude 전용 요청들을 통합 처리

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 처리 여부
        """
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path

        # Claude가 아니면 스킵
        if "claude.ai" not in host:
            return False

        # completion 요청에서 files[] uuid 교체
        if method == "POST" and "/completion" in path:
            return self.modify_completion_files(flow, cache_manager)

        return False
