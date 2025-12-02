from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, Tuple
import json
import logging
import base64

# -------------------------------
# ChatGPT Adapter (통합됨)
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """ChatGPT 전용 프롬프트 추출 - author.role == 'user'인 경우만"""
        try:
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    author = last_message.get("author", {})
                    if author.get("role") == "user":
                        content = last_message.get("content", {})
                        parts = content.get("parts", [])
                        # 문자열 타입의 프롬프트를 찾음
                        text_parts = [part for part in parts if isinstance(part, str)]
                        if text_parts:
                            return text_parts[0][:1000]
            return None
        except Exception:
            return None

    def should_modify(self, host: str, content_type: str) -> bool:
        """ChatGPT 변조 대상 확인"""
        return (
            "chatgpt.com" in host and
            "application/json" in content_type
        )



    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """ChatGPT 요청 데이터 변조 (멀티모달 대응 + 디버그 로그 강화)"""
        try:
            print(f"[DEBUG] modify_request_data 시작 - host={host}")

            messages = request_data.get("messages", [])
            if not messages:
                print("[DEBUG] 메시지 없음 - 수정 불가")
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})

            if author.get("role") != "user":
                print("[DEBUG] 마지막 메시지가 user가 아님 - 수정 스킵")
                return False, None

            content = last_message.get("content", {})
            parts = content.get("parts", [])

            print(f"[DEBUG] parts 구조: {parts}")
            print(f"[DEBUG] parts 개수: {len(parts)}")

            if not parts:
                print("[DEBUG] parts 없음 - 수정 불가")
                return False, None

            replaced = False

            # parts 전체를 순회하며 문자열 part 찾아 수정
            for idx, part in enumerate(parts):
                print(f"[DEBUG] part[{idx}] type: {type(part)}")

                if isinstance(part, str):
                    print(f"[DEBUG] 텍스트 part 발견! index={idx}")
                    parts[idx] = modified_prompt
                    replaced = True
                    break

            if not replaced:
                print("[DEBUG] 치환할 문자열 part 없음 - 멀티모달 only?")
                return False, None

            # JSON → 바이너리 변환
            modified_content = json.dumps(
                request_data,
                ensure_ascii=False
            ).encode('utf-8')

            print(f"[DEBUG] 수정 완료! 최종 바이트 길이={len(modified_content)}")
            return True, modified_content

        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None



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
                import json as json_lib
                data = json_lib.loads(content_str)

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
            import json as json_lib
            data = json_lib.loads(content_str)

            original_size = data.get('file_size', 0)
            data['file_size'] = modified_size

            # 수정된 JSON으로 교체
            modified_content = json_lib.dumps(data).encode('utf-8')
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
            import traceback
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
            import traceback
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
            flow.request.set_content(modified_bytes)

            # Content-Length 업데이트
            flow.request.headers["content-length"] = str(len(modified_bytes))

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
            import traceback
            traceback.print_exc()
            return False

    def send_new_post_request(self, original_flow: http.HTTPFlow, modified_file_size: int) -> tuple:
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
            import traceback
            traceback.print_exc()
            return (False, None)


    # ===== ChatGPT 전용 file_id 교체 메서드들 =====

    def modify_analytics_request(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """ChatGPT analytics 요청 (/ces/v1/t)에서 file_id & fileSize 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            body_str = flow.request.content.decode('utf-8')
            body_data = json.loads(body_str)

            properties = body_data.get('properties', {})
            original_file_id = properties.get('fileId')

            if original_file_id:
                event_name = body_data.get('event', 'unknown')
                logging.info(f"[ChatGPT Analytics] 요청 감지: {event_name}")
                logging.info(f"[ChatGPT Analytics] 원본 file_id: {original_file_id}")

                # 캐시에서 전체 매핑 정보 조회 (file_id + size)
                mapping = cache_manager.get_file_mapping(original_file_id)

                if mapping:
                    new_file_id = mapping.get('new_file_id')
                    new_size = mapping.get('new_size')

                    # file_id 교체
                    if new_file_id:
                        new_file_id_with_prefix = f"file_{new_file_id.replace('-', '')}"
                        properties['fileId'] = new_file_id_with_prefix
                        logging.info(f"[ChatGPT Analytics] ✓ file_id 교체: {original_file_id} → {new_file_id_with_prefix}")

                    # fileSize 교체
                    if 'fileSize' in properties and new_size:
                        original_size = properties['fileSize']
                        properties['fileSize'] = new_size
                        logging.info(f"[ChatGPT Analytics] ✓ fileSize 교체: {original_size} → {new_size}")

                    # body 업데이트
                    body_data['properties'] = properties
                    new_body_str = json.dumps(body_data)

                    # 요청 body 변조
                    flow.request.content = new_body_str.encode('utf-8')
                    flow.request.headers['content-length'] = str(len(new_body_str))

                    logging.info(f"[ChatGPT Analytics] 변조된 요청 전송 →")
                    return True
                else:
                    logging.info(f"[ChatGPT Analytics] ⚠ 매핑 정보 없음 - 원본 그대로 전송")
        except Exception:
            pass
        return False


    def modify_file_get_request(self, flow: http.HTTPFlow, cache_manager) -> bool:
        """ChatGPT 파일 GET 요청에서 file_id 교체

        Args:
            flow: mitmproxy HTTPFlow 객체
            cache_manager: FileCacheManager 인스턴스

        Returns:
            bool: 수정 여부
        """
        try:
            import re
            path = flow.request.path

            # URL에서 file_id 추출 (file_XXXXX 형식)
            match = re.search(r'(file_[a-f0-9]+)', path)
            if match:
                original_file_id = match.group(1)
                logging.info(f"[ChatGPT] 파일 GET 요청 감지")
                logging.info(f"[ChatGPT] 원본 file_id: {original_file_id}")
                logging.info(f"[ChatGPT] 원본 URL: {flow.request.url}")

                # 캐시에서 새 file_id 조회
                new_file_id = cache_manager.get_new_file_id(original_file_id)

                if new_file_id:
                    # file_id 교체
                    new_file_id_with_prefix = f"file_{new_file_id.replace('-', '')}"

                    # URL 변경
                    old_url = flow.request.url
                    new_url = old_url.replace(original_file_id, new_file_id_with_prefix)
                    flow.request.url = new_url
                    flow.request.path = flow.request.path.replace(original_file_id, new_file_id_with_prefix)

                    logging.info(f"[ChatGPT] ✓ file_id 교체: {original_file_id} → {new_file_id_with_prefix}")
                    logging.info(f"[ChatGPT] ✓ 새 URL: {new_url}")
                    logging.info(f"[ChatGPT] 변조된 요청 전송 →")
                    return True
                else:
                    logging.info(f"[ChatGPT] ⚠ 매핑된 file_id 없음 - 원본 그대로 전송")
        except Exception as e:
            logging.info(f"[ChatGPT] 파일 GET 처리 오류: {e}")
            import traceback
            traceback.print_exc()
        return False


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
                    logging.info(f"[ChatGPT] ⚠ 매핑된 file_id 없음 - 원본 그대로 전송")
        except Exception as e:
            logging.info(f"[ChatGPT] /process_upload_stream 처리 오류: {e}")
            import traceback
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
            import traceback
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

        # 1. Analytics 요청 처리
        if method == "POST" and "/ces/v1/t" in path:
            return self.modify_analytics_request(flow, cache_manager)

        # 2. 파일 GET 요청 처리
        if method == "GET" and "/backend-api/files/" in path:
            return self.modify_file_get_request(flow, cache_manager)

        # 3. process_upload_stream 처리
        if method == "POST" and "/process_upload_stream" in path:
            return self.modify_process_upload_stream(flow, cache_manager)

        # 4. 메시지 attachments 처리
        if method == "POST" and "conversation" in path and "/backend-api/" in path:
            return self.modify_message_attachments(flow, cache_manager)

        return False
