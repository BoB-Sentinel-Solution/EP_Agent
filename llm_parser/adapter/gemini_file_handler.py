#!/usr/bin/env python3
"""
Gemini File Handler - Gemini 파일 업로드/변조 처리 전용 핸들러
ChatGPT와 유사한 2단계 업로드 (POST → POST with upload_id)
"""
from typing import Dict, Any, Optional, Tuple
from mitmproxy import http
from urllib.parse import unquote_plus, parse_qs
import base64
import json
import logging
import traceback
import re
import requests
from copy import deepcopy
from llm_parser.adapter.base_file_handler import BaseFileHandler

class GeminiFileHandler(BaseFileHandler):
    """Gemini 파일 업로드/변조 처리 핸들러"""

    def __init__(self, server_client, cache_manager):
        """
        Args:
            server_client: 서버 통신 클라이언트
            cache_manager: 파일 캐시 매니저
        """
        super().__init__(server_client)
        self.cache_manager = cache_manager


    # ===== 1단계: 첫 번째 POST 처리 (메타데이터) =====

    def extract_file_registration_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """첫 번째 POST 요청에서 파일 메타데이터 추출 (upload_id 없음)

        Returns:
            {
                "file_name": str,
                "file_size": int,
                "content_type": str
            }
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # Gemini 업로드 호스트 확인
            if "push.clients6.google.com" not in host:
                return None

            # POST /upload/ (upload_id 없음)
            if method != "POST" or path != "/upload/":
                return None

            # x-goog-upload-command: start 확인
            upload_command = flow.request.headers.get("x-goog-upload-command", "")
            if upload_command != "start":
                return None

            # 파일 크기 추출 (헤더)
            file_size_str = flow.request.headers.get("x-goog-upload-header-content-length")
            if not file_size_str:
                logging.error("[Gemini] x-goog-upload-header-content-length 헤더 없음")
                return None

            file_size = int(file_size_str)

            # 파일명 추출 (body에서)
            content_type = flow.request.headers.get("content-type", "")
            file_name = "unknown"

            if "application/x-www-form-urlencoded" in content_type:
                try:
                    body = flow.request.content.decode('utf-8', errors='ignore')

                    # File name: 파일명.확장자 형태 (이미 UTF-8 디코딩된 상태)
                    match = re.search(r"File name: (.+?)(?:\n|$)", body)
                    if match:
                        file_name = match.group(1).strip()
                        logging.info(f"[Gemini] 파일명 추출 성공: {file_name}")
                    else:
                        logging.warning(f"[Gemini] 파일명 추출 실패 - regex 매칭 안됨")
                        logging.info(f"[Gemini DEBUG] Body 내용: {body[:200]}")
                except Exception as e:
                    logging.warning(f"[Gemini] 파일명 추출 실패: {e}")
                    traceback.print_exc()

            logging.info(f"[Gemini] 첫 번째 POST 감지: {file_name} ({file_size} bytes)")

            return {
                "file_name": file_name,
                "file_size": file_size,
                "content_type": flow.request.headers.get("content-type", "")
            }

        except Exception as e:
            logging.error(f"[Gemini] 첫 번째 POST 추출 오류: {e}")
            traceback.print_exc()
            return None


    # ===== 2단계: 두 번째 POST 처리 (실제 파일) =====

    def handle_file_upload(
        self,
        flow: http.HTTPFlow,
        host: str,
        public_ip: str,
        private_ip: str,
        hostname: str
    ) -> bool:
        """Gemini 파일 업로드 전체 처리 (POST /upload?upload_id=... 요청)

        ChatGPT 방식:
        1. 파일 추출 & 서버 통신
        2. 첫 번째 POST 다시 전송 (변조된 크기로)
        3. 새 upload_id 받음
        4. 현재 flow의 upload_id 교체
        5. 파일 데이터 변조

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
            original_upload_id = upload_file_info.get("upload_id")

            # 안전한 base64 디코딩 및 로깅
            self._safe_decode_file_data(attachment, file_name, "Gemini POST", file_format)

            # ===== 캐시에서 원본 파일명 가져오기 (서버 전송 전에!) =====
            cached_data = self.cache_manager.get_recent_gemini_post()
            if cached_data:
                metadata = cached_data["metadata"]
                if metadata.get("file_name"):
                    file_name = metadata.get("file_name")
                    # 확장자 추출 (docx, pdf 등)
                    file_format = file_name.split('.')[-1] if '.' in file_name else file_format
                    attachment["format"] = file_format
                    logging.info(f"[Gemini] 원본 파일명 복원: {file_name} (format: {file_format})")

            # 서버로 파일 정보 전송 → 변조 정보 받기
            # host 정규화: push.clients6.google.com → gemini.google.com
            normalized_host = "gemini.google.com" if "push.clients6.google.com" in host else host

            file_log_entry = self._create_file_log_entry(
                public_ip, private_ip, normalized_host, hostname, file_name, attachment
            )

            file_change, modified_file_data, modified_file_size = self._send_file_to_server(
                file_log_entry, "Gemini"
            )

            if not file_change:
                logging.info(f"[Gemini] 파일 변조 안함")
                return True

            if not modified_file_data:
                logging.info(f"[Gemini] ⚠ 변조할 파일 데이터 없음")
                return True

            # ===== ChatGPT 방식: 새 POST 요청 생성 =====
            logging.info(f"[Gemini] 파일 변조 시작: {file_format} ({modified_file_size} bytes)")

            # 캐시에서 첫 번째 POST flow 가져오기 (이미 위에서 조회했지만 한번 더 확인)
            if not cached_data:
                cached_data = self.cache_manager.get_recent_gemini_post()
                if not cached_data:
                    logging.error("[Gemini] ✗ 첫 번째 POST를 캐시에서 찾을 수 없음")
                    return False

            original_flow = cached_data["flow"]
            metadata = cached_data["metadata"]

            logging.info(f"[Gemini] 첫 번째 POST 복사: {file_name} ({metadata.get('file_size')} bytes)")

            # 새 POST 전송 (변조된 크기로)
            success, new_upload_id = self.send_new_post_request(
                original_flow,
                modified_file_size,
                metadata
            )

            if not success or not new_upload_id:
                logging.error("[Gemini] ✗ 새 POST 전송 실패")
                return False

            logging.info(f"[Gemini] ✓ 새 upload_id 받음: {new_upload_id[:50]}...")

            # upload_id 매핑 저장
            self.cache_manager.save_file_id_mapping(
                original_file_id=original_upload_id,
                new_file_id=new_upload_id,
                original_size=metadata.get("file_size"),
                new_size=modified_file_size
            )

            # 현재 flow의 upload_id 교체
            new_path = flow.request.path.replace(original_upload_id, new_upload_id)
            flow.request.path = new_path

            # 파일 데이터 변조
            success = self.modify_binary_body(flow, modified_file_data)

            if success:
                logging.info(f"[Gemini] ✓ 파일 변조 완료")
            else:
                logging.info(f"[Gemini] ✗ 파일 변조 실패")

            return True

        except Exception as e:
            logging.error(f"[Gemini] 파일 업로드 처리 오류: {e}")
            traceback.print_exc()
            return False


    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 업로드 POST 요청 감지 및 파일 데이터 추출 (upload_id 있음)

        Returns:
            {
                "attachment": {"format": str, "data": str},
                "file_name": str,
                "upload_id": str
            }
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # Gemini 업로드 호스트가 아니면 None
            if "push.clients6.google.com" not in host:
                return None

            # POST /upload가 아니면 None
            if method != "POST" or "/upload" not in path:
                return None

            # upload_id 파라미터가 없으면 None (첫 번째 메타데이터 POST 제외)
            if "upload_id=" not in path:
                return None

            # upload_protocol=resumable 확인
            if "upload_protocol=resumable" not in path:
                return None

            logging.info(f"[Gemini] POST /upload?upload_id=... 감지 (resumable upload)")

            # upload_id 추출
            match = re.search(r'upload_id=([^&]+)', path)
            if not match:
                logging.error("[Gemini] upload_id 추출 실패")
                return None

            upload_id = match.group(1)

            # body는 순수 바이너리 데이터
            content = flow.request.content

            if not content or len(content) < 100:
                logging.info("[Gemini] 파일 데이터가 너무 작음")
                return None

            # 파일 형식 추정 (magic bytes)
            file_format = self._detect_file_format(content)
            file_name = f"upload.{file_format}" if file_format != "unknown" else "upload.bin"

            # base64 인코딩
            encoded_data = base64.b64encode(content).decode('utf-8')

            logging.info(f"[Gemini] 파일 추출 성공: {file_name} ({len(content)} bytes, {file_format})")

            return {
                "attachment": {
                    "format": file_format,
                    "data": encoded_data
                },
                "file_name": file_name,
                "upload_id": upload_id
            }

        except Exception as e:
            logging.error(f"[Gemini] 파일 추출 중 오류: {e}")
            traceback.print_exc()
            return None




    def send_new_post_request(
        self,
        original_flow: http.HTTPFlow,
        modified_file_size: int,
        metadata: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """첫 번째 POST를 변조된 크기로 다시 전송하여 새 upload_id 받기

        Args:
            original_flow: 원본 첫 번째 POST flow
            modified_file_size: 변조된 파일 크기
            metadata: 파일 메타데이터

        Returns:
            (success, new_upload_id)
        """
        try:
            # 원본 요청 복사
            headers = dict(original_flow.request.headers)

            # x-goog-upload-header-content-length 변조
            headers["x-goog-upload-header-content-length"] = str(modified_file_size)

            # URL 구성
            url = f"https://{original_flow.request.pretty_host}{original_flow.request.path}"

            # body 복사
            body = original_flow.request.content

            logging.info(f"[Gemini POST] 새 POST 전송 시작...")
            logging.info(f"[Gemini POST] URL: {url}")
            logging.info(f"[Gemini POST] 변조된 크기: {modified_file_size} bytes")

            # 세션 생성 (프록시 우회)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # POST 요청 전송
            response = session.post(
                url,
                headers=headers,
                data=body,
                verify=True,
                timeout=30
            )

            logging.info(f"[Gemini POST] 응답 상태: {response.status_code}")

            if response.status_code not in [200, 201]:
                logging.error(f"[Gemini POST] ✗ 새 POST 실패: {response.status_code}")
                logging.error(f"[Gemini POST] Response: {response.text[:200]}")
                return False, None

            # upload_id 추출 (응답 헤더에서)
            new_upload_id = response.headers.get("x-guploader-uploadid")

            if not new_upload_id:
                # URL에서 추출 시도
                location = response.headers.get("location", "")
                if "upload_id=" in location:
                    match = re.search(r'upload_id=([^&]+)', location)
                    if match:
                        new_upload_id = match.group(1)

            if not new_upload_id:
                logging.error("[Gemini POST] ✗ 새 upload_id 추출 실패")
                logging.error(f"[Gemini POST] Response headers: {dict(response.headers)}")
                return False, None

            logging.info(f"[Gemini POST] ✓ 새 POST 성공, upload_id: {new_upload_id[:50]}...")
            return True, new_upload_id

        except Exception as e:
            logging.error(f"[Gemini POST] 새 POST 전송 오류: {e}")
            traceback.print_exc()
            return False, None


    def modify_binary_body(self, flow: http.HTTPFlow, modified_file_data: str) -> bool:
        """body를 변조된 파일 데이터로 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_file_data: base64 인코딩된 변조할 파일 데이터

        Returns:
            bool: 변조 성공 여부
        """
        try:
            # base64 디코딩
            modified_bytes = base64.b64decode(modified_file_data)
            original_length = len(flow.request.content)

            # body 교체
            self._set_request_content(flow, modified_bytes)

            # 변조 전후 로깅
            self._log_request_before_after(
                flow, "Gemini POST", original_length, len(modified_bytes)
            )

            logging.info(f"[Gemini] 파일 데이터 변조 완료")
            return True

        except Exception as e:
            logging.error(f"[Gemini] 파일 변조 실패: {e}")
            traceback.print_exc()
            return False


    # ===== 응답에서 file_path 추출 =====

    def extract_file_path_from_response(self, flow: http.HTTPFlow) -> Optional[str]:
        """업로드 응답에서 file_path 추출

        Returns:
            str: file_path (예: /contrib_service/ttl_1d/xxx...)
        """
        try:
            host = flow.request.pretty_host
            path = flow.request.path

            # Gemini 업로드 응답이 아니면 None
            if "push.clients6.google.com" not in host or "/upload" not in path:
                return None

            # upload_id가 있는 요청만 처리
            if "upload_id=" not in path:
                return None

            # 응답 body가 file_path
            response_content = flow.response.content.decode('utf-8', errors='ignore').strip()

            # /contrib_service/ttl_1d/로 시작하는지 확인
            if not response_content.startswith('/contrib_service/'):
                logging.error(f"[Gemini] 예상치 못한 응답 형식: {response_content[:100]}")
                return None

            logging.info(f"[Gemini] 파일 경로 추출 성공: {response_content[:50]}...")
            return response_content

        except Exception as e:
            logging.error(f"[Gemini] 파일 경로 추출 실패: {e}")
            traceback.print_exc()
            return None


    # ===== 프롬프트 요청에서 file_path 교체 =====

    def modify_prompt_file_paths(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """Gemini 프롬프트 요청에서 f.req 내부의 file_path 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            # f.req 파라미터 추출
            form_data = flow.request.urlencoded_form
            if not form_data or 'f.req' not in form_data:
                return False

            f_req_str = form_data.get('f.req')
            if not f_req_str:
                return False

            # URL 디코딩
            decoded_str = unquote_plus(f_req_str)

            # 외부 JSON 파싱
            try:
                outer_array = json.loads(decoded_str)
            except json.JSONDecodeError:
                logging.error("[Gemini] f.req 외부 JSON 파싱 실패")
                return False

            if not isinstance(outer_array, list) or len(outer_array) < 2:
                return False

            # 내부 JSON 파싱
            inner_array_str = outer_array[1]
            try:
                inner_data = json.loads(inner_array_str)
            except json.JSONDecodeError:
                logging.error("[Gemini] f.req 내부 JSON 파싱 실패")
                return False

            if not isinstance(inner_data, list) or not inner_data:
                return False

            # 파일 첨부 정보 확인: inner_data[0][3]
            if len(inner_data[0]) < 4 or not inner_data[0][3]:
                # 파일 첨부 없음
                return False

            attachments = inner_data[0][3]
            if not isinstance(attachments, list) or not attachments:
                return False

            logging.info(f"[Gemini Prompt] 파일 첨부 감지, attachments: {len(attachments)}개")

            modified = False

            # 각 첨부 파일의 경로 교체
            for attachment in attachments:
                if not isinstance(attachment, list) or not attachment:
                    continue

                # attachment[0][0][0]이 file_path
                if len(attachment) < 1 or not isinstance(attachment[0], list):
                    continue

                if len(attachment[0]) < 1 or not isinstance(attachment[0][0], list):
                    continue

                if len(attachment[0][0]) < 1:
                    continue

                original_path = attachment[0][0][0]

                if not isinstance(original_path, str) or not original_path.startswith('/contrib_service/'):
                    continue

                # 캐시에서 매핑 조회
                new_path = cache_manager.get_new_file_id(original_path)

                if new_path:
                    logging.info(f"[Gemini Prompt] ✓ 경로 교체: {original_path[:50]}... → {new_path[:50]}...")
                    attachment[0][0][0] = new_path
                    modified = True
                else:
                    # 매핑 없으면 원본 사용
                    logging.info(f"[Gemini Prompt] 매핑 없음, 원본 사용: {original_path[:50]}...")

            if not modified:
                return False

            # 변조된 데이터를 다시 JSON으로 직렬화
            new_inner_str = json.dumps(inner_data, ensure_ascii=False, separators=(',', ':'))
            outer_array[1] = new_inner_str

            new_outer_str = json.dumps(outer_array, ensure_ascii=False, separators=(',', ':'))

            # URL 인코딩 (unquote_plus의 역과정)
            from urllib.parse import quote_plus
            new_f_req = quote_plus(new_outer_str)

            # form_data 업데이트
            form_data['f.req'] = new_f_req

            # 새로운 body 생성
            from urllib.parse import urlencode
            new_body = urlencode(form_data, doseq=True)

            # 요청 body 변조
            flow.request.content = new_body.encode('utf-8')
            flow.request.headers['content-length'] = str(len(new_body))

            logging.info(f"[Gemini Prompt] ✓ f.req 파일 경로 교체 완료")
            return True

        except Exception as e:
            logging.error(f"[Gemini Prompt] 처리 오류: {e}")
            traceback.print_exc()
            return False


    # ===== 통합 Gemini 요청 처리 =====

    def process_gemini_specific_requests(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """Gemini 전용 요청들을 통합 처리

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 처리 여부
        """
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path

        # Gemini 프롬프트 요청에서 파일 경로 교체
        if method == "POST" and "gemini.google.com" in host:
            content_type = flow.request.headers.get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in content_type:
                return self.modify_prompt_file_paths(flow, cache_manager)

        return False
