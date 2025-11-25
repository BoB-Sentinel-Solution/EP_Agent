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
            file_format = self._extract_format_from_content_type(content_type)

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

    def _extract_format_from_content_type(self, content_type: str) -> str:
        """Content-Type에서 파일 포맷 추출"""
        if "image/" in content_type:
            return content_type.split("/")[1].split(";")[0]
        elif "application/pdf" in content_type:
            return "pdf"
        elif "text/csv" in content_type:
            return "csv"
        elif "application/vnd.openxmlformats-officedocument.presentationml.presentation" in content_type:
            return "pptx"
        elif "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in content_type:
            return "docx"
        elif "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in content_type:
            return "xlsx"
        else:
            return "unknown"

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
