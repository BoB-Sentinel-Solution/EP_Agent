#!/usr/bin/env python3
"""
ChatGPT File Handler - ChatGPT 파일 업로드/변조 처리 전용 핸들러
"""
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from mitmproxy import http
import base64
import json
import logging
import traceback
from llm_parser.common.utils import FileUtils
from llm_parser.adapter.base_file_handler import BaseFileHandler


class ChatGPTFileHandler(BaseFileHandler):
    """ChatGPT 파일 업로드/변조 처리 핸들러"""

    def __init__(self, server_client, cache_manager, log_manager):
        """
        Args:
            server_client: 서버 통신 클라이언트
            cache_manager: 파일 캐시 매니저
            log_manager: 로그 매니저
        """
        super().__init__(server_client)
        self.cache_manager = cache_manager
        self.log_manager = log_manager


    # ===== 파일 등록/업로드 핵심 메소드 =====

    def handle_file_upload(
        self,
        flow: http.HTTPFlow,
        host: str,
        public_ip: str,
        private_ip: str,
        hostname: str
    ) -> bool:
        """ChatGPT 파일 업로드 전체 처리 (PUT 요청)

        Returns:
            bool: 처리 완료 여부
        """
        try:
            # 파일 정보 추출
            put_file_info = self.extract_file_from_upload_request(flow)
            if not put_file_info or not put_file_info.get("file_id"):
                return False

            attachment = put_file_info["attachment"]
            file_id = put_file_info["file_id"]

            # file_id를 process_upload_stream 형식으로 변환 (하이픈 제거 + file_ prefix)
            # 예: "00000000-5c0c-7206-8dab-268c529b800a" → "file_000000005c0c72068dab268c529b800a"
            if '-' in file_id:
                file_id_for_mapping = f"file_{file_id.replace('-', '')}"
            elif not file_id.startswith('file_'):
                file_id_for_mapping = f"file_{file_id}"
            else:
                file_id_for_mapping = file_id

            # 안전한 base64 디코딩 및 로깅
            self._safe_decode_file_data(attachment, file_id, "ChatGPT PUT", attachment.get('format'))
            logging.info(f"[ChatGPT PUT] 매핑용 file_id: {file_id_for_mapping}")

            # 캐시에서 POST 메타데이터 가져오기
            post_data = self.cache_manager.get_recent_chatgpt_post()

            if not post_data:
                logging.info(f"[ChatGPT PUT] ⚠ 매칭되는 POST 없음")
                return True

            # 서버로 파일 정보 전송 → 변조 정보 받기
            metadata = post_data["metadata"]
            attachment["size"] = metadata.get("file_size", 0)

            file_log_entry = self._create_file_log_entry(
                public_ip, private_ip, host, hostname, metadata.get('file_name'), attachment
            )

            file_change, modified_file_data, modified_file_size = self._send_file_to_server(
                file_log_entry, "ChatGPT"
            )

            if not file_change:
                logging.info(f"[ChatGPT] 파일 변조 안함")
                return True

            if not modified_file_data:
                logging.info(f"[ChatGPT] 변조할 파일 데이터 없음")
                return True

            if not modified_file_size:
                modified_file_size = metadata.get("file_size")

            # 파일 포맷에 따라 처리 분기
            file_format = attachment.get("format", "").lower()
            is_image = file_format in ["png", "jpg", "jpeg", "gif", "webp", "bmp"]

            if is_image:
                # 이미지: PUT body만 변조 (크기 동일)
                logging.info(f"[ChatGPT] 이미지 파일 변조: {file_format} ({modified_file_size} bytes)")
                success = self.modify_file_data(flow, modified_file_data)
                if success:
                    logging.info(f"[ChatGPT] ✓ 이미지 변조 완료")
                else:
                    logging.info(f"[ChatGPT] ✗ 이미지 변조 실패")
            else:
                # 문서 파일: 새 POST 생성 후 처리 (크기 변경 가능)
                logging.info(f"[ChatGPT] 문서 파일 변조: {file_format} ({metadata.get('file_size')} → {modified_file_size} bytes)")
                self._process_document_file(
                    post_data,
                    flow,
                    {
                        "format": attachment.get("format"),
                        "size": modified_file_size,
                        "data": modified_file_data,
                        "file_change": True
                    },
                    public_ip,
                    private_ip,
                    hostname,
                    original_file_id=file_id_for_mapping  # 변환된 file_id 전달 (process_upload_stream 형식)
                )
                logging.info(f"[ChatGPT] ✓ 문서 파일 위변조 완료")

            return True

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 업로드 처리 오류: {e}")
            traceback.print_exc()
            return False


    def _process_document_file(
        self,
        post_data: Dict[str, Any],
        put_flow: http.HTTPFlow,
        modified_attachment: Dict[str, Any],
        public_ip: str,
        private_ip: str,
        hostname: str,
        original_file_id: str = None
    ):
        """문서 파일 변조 처리 (새 POST 생성)

        Args:
            original_file_id: PUT URL에서 추출한 원본 file_id (process_upload_stream에서 사용될 ID)
        """
        post_flow = post_data["flow"]
        metadata = post_data["metadata"]
        modified_file_size = modified_attachment.get("size")
        modified_file_data = modified_attachment.get("data")

        logging.info(f"[ChatGPT] 파일 위변조: {metadata.get('file_name')} ({metadata.get('file_size')} → {modified_file_size} bytes)")
        logging.info(f"[ChatGPT] 원본 file_id (PUT URL): {original_file_id}")

        # 1. 새로운 POST 전송
        success, upload_url = self.send_new_post_request(post_flow, modified_file_size)

        if not success or not upload_url:
            logging.info(f"[ChatGPT] ✗ 새 POST 전송 실패")
            return

        logging.info(f"[ChatGPT] ✓ 새 POST 전송 성공")

        # file_id 매핑 저장
        new_file_id = upload_url.split('/files/')[1].split('/')[0] if '/files/' in upload_url else None

        if new_file_id:
            if original_file_id:
                # PUT URL의 file_id를 그대로 사용 (이미 file_ prefix 포함)
                # 하이픈이 없는 형식이므로 그대로 사용
                original_size = metadata.get('file_size') if metadata else None
                self.cache_manager.save_file_id_mapping(
                    original_file_id,  # 이미 "file_xxxxx..." 형식
                    new_file_id,      # "00000000-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 형식
                    original_size=original_size,
                    new_size=modified_file_size
                )
                logging.info(f"[ChatGPT] ✓ file_id 매핑: {original_file_id} → {new_file_id}")
            else:
                logging.info(f"[ChatGPT] 원본 file_id 없음")
        else:
            logging.info(f"[ChatGPT] 새 file_id 추출 실패")

        # 2. PUT 요청 수정 (URL + 파일 데이터)
        put_flow.request.url = upload_url

        # 파일 데이터 변조
        success = self.modify_file_data(put_flow, modified_file_data)
        if not success:
            logging.info(f"[ChatGPT PUT] ✗ 파일 데이터 변조 실패")
            return

        # 로그 저장
        log_entry = {
            "time": datetime.now().isoformat(),
            "public_ip": public_ip,
            "private_ip": private_ip,
            "host": "chatgpt.com",
            "PCName": hostname,
            "prompt": f"[FILE: {metadata.get('file_name')}]",
            "attachment": modified_attachment,
            "interface": "llm",
            "holding_time": 0
        }
        self.log_manager.save_log(log_entry)


    def extract_file_registration_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 등록 POST 요청 감지 및 메타데이터 추출
        반환: {"file_name": str, "file_size": int, "use_case": str}
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # POST /backend-api/files 또는 /backend-anon/files
            if method != "POST":
                return None

            if "chatgpt.com" not in host:
                return None

            if not ("/backend-api/files" in path or "/backend-anon/files" in path or "/files" in path):
                return None

            # JSON 파싱
            try:
                content = flow.request.get_content()
                content_str = content.decode('utf-8', errors='ignore')
                data = json.loads(content_str)

                logging.info(f"[ChatGPT] 파일 등록 POST 감지: {data}")
                return data

            except Exception as e:
                logging.error(f"[ChatGPT] 파일 등록 요청 파싱 실패: {e}")
                return None

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 등록 요청 처리 오류: {e}")
            return None


    def modify_file_registration_size(self, flow: http.HTTPFlow, modified_size: int) -> bool:
        """파일 등록 요청의 file_size 수정

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_size: 변조된 파일 크기

        Returns:
            bool: 수정 성공 여부
        """
        try:
            content = flow.request.get_content()
            content_str = content.decode('utf-8', errors='ignore')
            data = json.loads(content_str)

            original_size = data.get('file_size', 0)
            data['file_size'] = modified_size

            # 수정된 JSON으로 교체
            modified_content = json.dumps(data).encode('utf-8')
            flow.request.set_content(modified_content)
            flow.request.headers["content-length"] = str(len(modified_content))

            logging.info(f"[ChatGPT] 파일 크기 수정: {original_size} → {modified_size}")
            return True

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 크기 수정 실패: {e}")
            return False


    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 업로드 요청 감지 및 파일 ID + 데이터 추출
        반환: {"file_id": str, "attachment": {"format": str, "data": str}}
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # ChatGPT 관련 호스트가 아니면 None
            if not ("chatgpt.com" in host or "oaiusercontent.com" in host):
                return None

            # PUT 방식 파일 업로드가 아니면 None
            if method != "PUT":
                return None

            # 스트리밍 업로드 처리: get_content()로 전체 데이터 읽기
            try:
                content = flow.request.get_content()
            except:
                content = flow.request.content

            # 파일 데이터가 없으면 None
            if not content or len(content) < 100:
                return None

            # File ID 추출 (URL 경로에서)
            file_id = self._extract_file_id_from_path(path)
            if not file_id:
                logging.error(f"[ChatGPT] File ID 추출 실패: {path}")
                return None

            content_type = flow.request.headers.get("content-type", "").lower()

            # base64 인코딩
            encoded_data = base64.b64encode(content).decode('utf-8')

            # 파일 포맷 추출
            file_format = FileUtils.extract_format_from_content_type(content_type)

            logging.info(f"[ChatGPT] PUT 파일 업로드 감지: {len(content)} bytes, format: {file_format}, file_id: {file_id}")

            return {
                "file_id": file_id,
                "attachment": {
                    "format": file_format,
                    "data": encoded_data
                }
            }

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 데이터 추출 중 오류: {e}")
            traceback.print_exc()
            return None


    def _extract_file_id_from_path(self, path: str) -> Optional[str]:
        """ChatGPT URL 경로에서 File ID 추출
        - /files/00000000-xxxx-xxxx-xxxx-xxxxxxxxxxxx/raw?... → 00000000-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        - /file-4f7MgRbWgv99N7o3ZmbnxB?... → file-4f7MgRbWgv99N7o3ZmbnxB
        """
        if '/files/' in path:
            try:
                return path.split('/files/')[1].split('/')[0]
            except (IndexError, AttributeError):
                return None
        elif '/file-' in path:
            try:
                file_id = path.split('/file-')[1].split('?')[0]
                return f"file-{file_id}"
            except (IndexError, AttributeError):
                return None
        return None


    def upload_modified_file(self, file_upload_info: dict, modified_file_data: str) -> bool:
        """변조된 파일로 실제 PUT 요청 생성 및 전송

        Args:
            file_upload_info: 원본 파일 업로드 정보 (method, url, headers)
            modified_file_data: base64 인코딩된 변조할 파일 데이터

        Returns:
            bool: 업로드 성공 여부
        """
        try:
            import requests

            # base64 디코딩
            modified_bytes = base64.b64decode(modified_file_data)

            # 헤더 준비
            headers = file_upload_info.get("headers", {}).copy()
            headers["content-length"] = str(len(modified_bytes))

            # URL 준비
            url = file_upload_info.get("url")

            logging.info(f"[ChatGPT] 변조된 파일 업로드 시작: {len(modified_bytes)} bytes → {url}")

            # 세션 생성 (프록시 무시)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # 새로운 PUT 요청 전송
            response = session.put(
                url,
                data=modified_bytes,
                headers=headers,
                timeout=30,
                verify=True
            )

            if response.status_code in [200, 201, 204]:
                logging.info(f"[ChatGPT] 변조된 파일 업로드 성공! status={response.status_code}")
                return True
            else:
                logging.error(f"[ChatGPT] 변조된 파일 업로드 실패: HTTP {response.status_code}")
                logging.error(f"[ChatGPT] Response: {response.text[:200]}")
                return False

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 업로드 중 오류: {e}")
            traceback.print_exc()
            return False


    def modify_file_data(self, flow: http.HTTPFlow, modified_file_data: str) -> bool:
        """파일 업로드 데이터 변조

        Args:
            flow: mitmproxy HTTPFlow 객체
            modified_file_data: base64 인코딩된 변조할 파일 데이터

        Returns:
            bool: 변조 성공 여부
        """
        try:
            # base64 디코딩
            modified_bytes = base64.b64decode(modified_file_data)

            # ===== 변조 전 원본 PUT 로깅 =====
            logging.info(f"[ChatGPT PUT] ===== 원본 PUT 패킷 =====")
            logging.info(f"[ChatGPT PUT] 원본 URL: {flow.request.url}")
            logging.info(f"[ChatGPT PUT] 원본 Method: {flow.request.method}")
            logging.info(f"[ChatGPT PUT] 원본 Body Length: {len(flow.request.content)} bytes")
            logging.info(f"[ChatGPT PUT] 원본 Headers:")
            for key, value in flow.request.headers.items():
                if key.lower() in ['cookie', 'authorization']:
                    logging.info(f"  {key}: {value[:50]}...")
                else:
                    logging.info(f"  {key}: {value}")
            logging.info(f"[ChatGPT PUT] =====================================")

            # PUT 요청의 body 교체
            self._set_request_content(flow, modified_bytes)

            # ===== 변조 후 PUT 로깅 =====
            logging.info(f"[ChatGPT PUT] ===== 변조된 PUT 패킷 =====")
            logging.info(f"[ChatGPT PUT] 변조된 URL: {flow.request.url}")
            logging.info(f"[ChatGPT PUT] 변조된 Method: {flow.request.method}")
            logging.info(f"[ChatGPT PUT] 변조된 Body Length: {len(flow.request.content)} bytes")
            logging.info(f"[ChatGPT PUT] 변조된 Headers:")
            for key, value in flow.request.headers.items():
                if key.lower() in ['cookie', 'authorization']:
                    logging.info(f"  {key}: {value[:50]}...")
                else:
                    logging.info(f"  {key}: {value}")

            # 파일 데이터 일부 확인 (첫 100바이트의 hex)
            logging.info(f"[ChatGPT PUT] 변조된 파일 데이터 (첫 100바이트 hex): {modified_bytes[:100].hex()}")
            logging.info(f"[ChatGPT PUT] =====================================")

            logging.info(f"[ChatGPT] 파일 데이터 변조 완료: {len(modified_bytes)} bytes")
            return True

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 변조 실패: {e}")
            traceback.print_exc()
            return False


    def send_new_post_request(self, original_flow: http.HTTPFlow, modified_file_size: int) -> tuple:
        """새로운 POST 요청 전송 (문서 파일 크기 변경 시)"""
        try:
            import requests

            # 원본 요청 정보 추출
            original_request = original_flow.request
            url = original_request.pretty_url
            headers = dict(original_request.headers)

            # 원본 body 파싱
            original_body = original_request.get_content().decode('utf-8', errors='ignore')
            body_data = json.loads(original_body)

            logging.info(f"[ChatGPT] 원본 POST: {body_data}")

            # file_size 변경
            original_size = body_data.get('file_size', 0)
            body_data['file_size'] = modified_file_size

            logging.info(f"[ChatGPT] 새 POST 생성: file_size {original_size} → {modified_file_size}")

            # 새로운 body 생성
            new_body = json.dumps(body_data)
            headers['content-length'] = str(len(new_body))

            # ===== 가짜 POST 패킷 상세 로깅 =====
            logging.info(f"[ChatGPT POST] ===== 가짜 POST 패킷 상세 =====")
            logging.info(f"[ChatGPT POST] URL: {url}")
            logging.info(f"[ChatGPT POST] Method: POST")
            logging.info(f"[ChatGPT POST] Headers:")
            for key, value in headers.items():
                # 민감한 헤더는 일부만 표시
                if key.lower() in ['cookie', 'authorization']:
                    logging.info(f"  {key}: {value[:50]}...")
                else:
                    logging.info(f"  {key}: {value}")
            logging.info(f"[ChatGPT POST] Body: {new_body}")
            logging.info(f"[ChatGPT POST] Body Length: {len(new_body)} bytes")
            logging.info(f"[ChatGPT POST] =====================================")

            # Cookie/Authorization 헤더 확인
            logging.info(f"[ChatGPT] Cookie 헤더: {headers.get('cookie', 'None')[:100]}...")
            logging.info(f"[ChatGPT] Authorization 헤더: {headers.get('authorization', 'None')[:50]}...")

            # 세션 생성 (프록시 우회)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {}

            # 새로운 POST 전송
            logging.info(f"[ChatGPT] 새 POST 전송 중...")
            response = session.post(
                url,
                data=new_body,
                headers=headers,
                timeout=30,
                verify=True
            )

            # ===== POST 응답 상세 로깅 =====
            logging.info(f"[ChatGPT POST] ===== POST 응답 상세 =====")
            logging.info(f"[ChatGPT POST] Status Code: {response.status_code}")
            logging.info(f"[ChatGPT POST] Response Headers:")
            for key, value in response.headers.items():
                logging.info(f"  {key}: {value}")
            logging.info(f"[ChatGPT POST] Response Body: {response.text[:500]}")
            logging.info(f"[ChatGPT POST] =====================================")

            if response.status_code in [200, 201]:
                logging.info(f"[ChatGPT] 새 POST 전송 성공! status={response.status_code}")

                # upload_url 추출
                try:
                    response_data = response.json()
                    upload_url = response_data.get('upload_url')

                    if upload_url:
                        logging.info(f"[ChatGPT] upload_url 추출 성공: {upload_url[:100]}...")

                        # upload_url에서 file_id 추출
                        if '/files/' in upload_url:
                            new_file_id = upload_url.split('/files/')[1].split('/')[0]
                            logging.info(f"[ChatGPT] 새로 생성된 file_id: {new_file_id}")

                        return (True, upload_url)
                    else:
                        logging.error(f"[ChatGPT] upload_url이 응답에 없음")
                        logging.error(f"[ChatGPT] 전체 응답: {response.text}")
                        return (False, None)
                except Exception as e:
                    logging.error(f"[ChatGPT] 응답 파싱 실패: {e}")
                    return (False, None)
            else:
                logging.error(f"[ChatGPT] 새 POST 전송 실패: HTTP {response.status_code}")
                logging.error(f"[ChatGPT] 응답: {response.text[:200]}")
                return (False, None)

        except Exception as e:
            logging.error(f"[ChatGPT] 새 POST 전송 중 오류: {e}")
            traceback.print_exc()
            return (False, None)


    # ===== ChatGPT 전용 file_id 교체 메서드들 =====


    def modify_process_upload_stream(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """ChatGPT process_upload_stream 요청에서 file_id 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            body_str = flow.request.content.decode('utf-8')
            body_data = json.loads(body_str)
            original_file_id = body_data.get('file_id')

            if original_file_id:
                logging.info(f"[ChatGPT] /process_upload_stream 요청 감지")
                logging.info(f"[ChatGPT] 원본 file_id: {original_file_id}")

                # 캐시에서 새 file_id 조회
                new_file_id = cache_manager.get_new_file_id(original_file_id)

                if new_file_id:
                    # file_id 교체
                    new_file_id_with_prefix = f"file_{new_file_id.replace('-', '')}"
                    body_data['file_id'] = new_file_id_with_prefix
                    new_body_str = json.dumps(body_data)

                    # 요청 body 변조
                    flow.request.content = new_body_str.encode('utf-8')
                    flow.request.headers['content-length'] = str(len(new_body_str))

                    logging.info(f"[ChatGPT] ✓ file_id 교체: {original_file_id} → {new_file_id_with_prefix}")
                    logging.info(f"[ChatGPT] 변조된 요청 전송 →")
                    return True
                else:
                    logging.info(f"[ChatGPT] 매핑된 file_id 없음 - 원본 그대로 전송")
        except Exception as e:
            logging.info(f"[ChatGPT] /process_upload_stream 처리 오류: {e}")
            traceback.print_exc()
        return False


    def modify_message_attachments(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """ChatGPT 메시지 요청에서 attachments file_id 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            body_str = flow.request.content.decode('utf-8')
            body_data = json.loads(body_str)
            path = flow.request.path

            logging.info(f"[ChatGPT Message] /backend-api/conversation 요청 감지")
            logging.info(f"[ChatGPT Message] 전체 경로: {path}")

            # messages[].metadata.attachments 찾기
            messages = body_data.get('messages', [])
            modified = False

            for msg_idx, message in enumerate(messages):
                metadata = message.get('metadata', {})
                attachments = metadata.get('attachments', [])

                for att_idx, attachment in enumerate(attachments):
                    original_file_id = attachment.get('id')
                    if original_file_id:
                        logging.info(f"[ChatGPT Message] 메시지[{msg_idx}] 첨부파일[{att_idx}] 감지: {original_file_id}")

                        # 캐시에서 매핑 정보 조회
                        mapping = cache_manager.get_file_mapping(original_file_id)

                        if mapping:
                            new_file_id = mapping.get('new_file_id')
                            new_size = mapping.get('new_size')

                            if new_file_id:
                                # file_id 교체
                                new_file_id_with_prefix = f"file_{new_file_id.replace('-', '')}"
                                attachment['id'] = new_file_id_with_prefix
                                logging.info(f"[ChatGPT Message] ✓ file_id 교체: {original_file_id} → {new_file_id_with_prefix}")
                                modified = True

                            # size 교체
                            if 'size' in attachment and new_size:
                                original_size = attachment['size']
                                attachment['size'] = new_size
                                logging.info(f"[ChatGPT Message] ✓ size 교체: {original_size} → {new_size}")
                        else:
                            logging.info(f"[ChatGPT Message] ⚠ 매핑 정보 없음: {original_file_id}")

            if modified:
                # body 업데이트
                new_body_str = json.dumps(body_data)
                flow.request.content = new_body_str.encode('utf-8')
                flow.request.headers['content-length'] = str(len(new_body_str))
                logging.info(f"[ChatGPT Message] ✓ 요청 body 변조 완료 - 이제 프롬프트 파싱 시작")
                return True
            else:
                logging.info(f"[ChatGPT Message] 첨부파일 없음 또는 매핑 없음 - 원본 그대로 진행")
        except Exception as e:
            logging.info(f"[ChatGPT Message] 처리 오류: {e}")
            traceback.print_exc()
        return False


    # ===== 통합 ChatGPT 요청 처리 =====

    def process_chatgpt_specific_requests(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """ChatGPT 전용 요청들을 통합 처리

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 처리 여부
        """
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path

        # ChatGPT가 아니면 스킵
        if "chatgpt.com" not in host and "oaiusercontent.com" not in host:
            return False

        # 3. process_upload_stream 처리
        if method == "POST" and "/process_upload_stream" in path:
            return self.modify_process_upload_stream(flow, cache_manager)

        # 4. 메시지 attachments 처리
        if method == "POST" and "conversation" in path and "/backend-api/" in path:
            return self.modify_message_attachments(flow, cache_manager)

        return False