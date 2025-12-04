from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, List, Tuple
import json
import base64
import logging
import re
import time

# -------------------------------
# Claude Adapter
# -------------------------------
class ClaudeAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Claude/Anthropic API 프롬프트 추출

        Note: CSV 등 extracted_content가 있는 경우 extract_prompt_with_attachments()를 사용해야 함
        """
        try:
            print(f"[DEBUG Claude extract_prompt] request_json 키들: {list(request_json.keys())}")

            # files 확인
            files = request_json.get("files", [])
            print(f"[DEBUG Claude extract_prompt] files 배열 크기: {len(files)}")
            if files:
                print(f"[DEBUG Claude extract_prompt] files 내용: {files}")

            # attachments 확인 (CSV 등 텍스트 파일은 extracted_content로 전송됨)
            attachments = request_json.get("attachments", [])
            print(f"[DEBUG Claude extract_prompt] attachments 배열 크기: {len(attachments)}")
            if attachments:
                print(f"[DEBUG Claude extract_prompt] attachments 내용 (첫 항목): {attachments[0] if len(attachments) > 0 else 'None'}")

            # Claude.ai 웹 인터페이스 - prompt 키 직접 확인
            prompt = request_json.get("prompt")
            if prompt and isinstance(prompt, str):
                print(f"[DEBUG Claude extract_prompt] prompt 길이: {len(prompt)}")

                # attachments에 extracted_content가 있는 경우 (CSV 등)
                if attachments:
                    for att in attachments:
                        if att.get("extracted_content"):
                            file_name = att.get("file_name", "unknown")
                            file_type = att.get("file_type", "unknown")
                            print(f"[DEBUG Claude extract_prompt] extracted_content 발견: {file_name} ({file_type})")

                return prompt[:1000]

            # Anthropic API - messages 패턴 확인
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                for message in reversed(messages):  # 최신 메시지부터 확인
                    if isinstance(message, dict) and message.get("role") == "user":
                        content = message.get("content")

                        # content가 문자열인 경우
                        if isinstance(content, str):
                            return content[:1000]

                        # content가 배열인 경우 (multimodal)
                        elif isinstance(content, list):
                            text_parts = []
                            for part in content:
                                if isinstance(part, dict) and part.get("type") == "text":
                                    text_parts.append(part.get("text", ""))
                            if text_parts:
                                return " ".join(text_parts)[:1000]

            return None
        except Exception:
            return None


    def should_modify(self, host: str, content_type: str) -> bool:
        """Claude 변조 대상 확인"""
        return (
            ("claude.ai" in host or "api.anthropic.com" in host) and
            "application/json" in content_type
        )

    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """Claude 요청 데이터 변조"""
        try:
            # Claude.ai 웹 인터페이스 - prompt 키 직접 수정
            if "prompt" in request_data and isinstance(request_data["prompt"], str):
                request_data["prompt"] = modified_prompt
                modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
                return True, modified_content

            # Anthropic API - messages 패턴 수정
            messages = request_data.get("messages", [])
            if isinstance(messages, list) and messages:
                for i, message in enumerate(reversed(messages)):
                    if isinstance(message, dict) and message.get("role") == "user":
                        content = message.get("content")

                        # content가 문자열인 경우
                        if isinstance(content, str):
                            # 실제 인덱스 계산 (reversed 때문에)
                            actual_index = len(messages) - 1 - i
                            request_data["messages"][actual_index]["content"] = modified_prompt
                            modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
                            return True, modified_content

                        # content가 배열인 경우 (multimodal) - 텍스트 부분만 수정
                        elif isinstance(content, list):
                            actual_index = len(messages) - 1 - i
                            for j, part in enumerate(content):
                                if isinstance(part, dict) and part.get("type") == "text":
                                    request_data["messages"][actual_index]["content"][j]["text"] = modified_prompt
                                    modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
                                    return True, modified_content

            return False, None
        except Exception as e:
            print(f"[ERROR] Claude 변조 실패: {e}")
            return False, None

    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """Claude.ai 파일 업로드 요청 감지 및 데이터 추출

        2가지 케이스:
        1) 이미지/PDF: POST /upload 또는 /convert_document (multipart/form-data)
        2) CSV 등: POST /completion에 attachments.extracted_content로 포함

        반환: {"file_id": str, "attachment": {...}}
        """
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            print(f"[DEBUG Claude] 요청 체크: {host} | {method} {path}")

            # Claude.ai 관련 호스트가 아니면 None
            if not ("claude.ai" in host or "api.anthropic.com" in host):
                return None

            # 1) multipart 업로드 엔드포인트 (이미지/PDF)
            is_multipart_upload = (method == "POST" and
                        ("/upload" in path or "/convert_document" in path or "/wiggle/upload-file" in path))

            # 2) JSON 기반 completion 요청 (CSV 등 extracted_content)
            is_completion = (method == "POST" and "/completion" in path)

            if not (is_multipart_upload or is_completion):
                print(f"[DEBUG Claude] 파일 업로드 엔드포인트 아님: {method} {path}")
                return None

            content_type = flow.request.headers.get("content-type", "").lower()

            # Case 1: multipart/form-data 업로드 (이미지/PDF)
            if is_multipart_upload and "multipart/form-data" in content_type:
                print(f"[DEBUG Claude] multipart 업로드 엔드포인트 감지!")
                return self._extract_multipart_file(flow, content_type)

            # Case 2: JSON completion with extracted_content (CSV)
            if is_completion and "application/json" in content_type:
                print(f"[DEBUG Claude] completion 요청, attachments 확인 중...")
                return self._extract_attachment_from_completion(flow)

            return None

        except Exception as e:
            logging.error(f"[Claude] 파일 업로드 감지 중 오류: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _extract_multipart_file(self, flow: http.HTTPFlow, content_type: str) -> Optional[Dict[str, Any]]:
        """multipart/form-data 파일 추출 (이미지/PDF)"""
        try:
            print(f"[DEBUG Claude] Content-Type: {content_type}")

            # multipart/form-data가 아니면 None
            if "multipart/form-data" not in content_type:
                print(f"[DEBUG Claude] multipart/form-data 아님")
                return None

            # boundary 추출
            boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
            if not boundary_match:
                logging.error("[Claude] multipart boundary를 찾을 수 없습니다")
                print(f"[DEBUG Claude] boundary 추출 실패")
                return None

            boundary = boundary_match.group(1)
            print(f"[DEBUG Claude] boundary: {boundary}")

            # 스트리밍 업로드 처리
            try:
                content = flow.request.get_content()
            except:
                content = flow.request.content

            print(f"[DEBUG Claude] content 크기: {len(content) if content else 0} bytes")

            if not content or len(content) < 100:
                print(f"[DEBUG Claude] content가 너무 작음 (< 100 bytes)")
                return None

            # multipart 파싱: 파일 데이터 추출
            file_data, file_name, file_format = self._parse_multipart(content, boundary)

            print(f"[DEBUG Claude] 파싱 결과 - file_data: {len(file_data) if file_data else 0} bytes, name: {file_name}, format: {file_format}")

            if not file_data:
                logging.error("[Claude] multipart 파일 데이터 추출 실패")
                print(f"[DEBUG Claude] 파일 데이터 추출 실패")
                return None

            # base64 인코딩
            encoded_data = base64.b64encode(file_data).decode('utf-8')

            logging.info(f"[Claude] POST 파일 업로드 감지: {len(file_data)} bytes, format: {file_format}, name: {file_name}")

            # 임시 file_id (타임스탬프 기반 - 시간순 매칭용)
            timestamp = int(time.time() * 1000)  # 밀리초
            temp_file_id = f"claude:{timestamp}:{file_name}"

            return {
                "file_id": temp_file_id,
                "attachment": {
                    "format": file_format,
                    "data": encoded_data
                },
                "pending_response": True,  # 응답 대기 플래그
                "file_name": file_name,
                "timestamp": timestamp
            }

        except Exception as e:
            logging.error(f"[Claude] multipart 파일 추출 중 오류: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _extract_attachment_from_completion(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """completion 요청에서 extracted_content 추출 (CSV 등)

        Note: CSV는 프롬프트와 함께 전송되므로 파일만 추출하고 None 반환
              프롬프트는 extract_prompt()에서 별도 처리됨
        """
        try:
            # JSON 본문 파싱
            body = flow.request.content.decode('utf-8', errors='replace')
            request_json = json.loads(body)

            attachments = request_json.get("attachments", [])
            if not attachments:
                print(f"[DEBUG Claude] attachments 없음")
                return None

            # extracted_content가 있는지만 확인
            for att in attachments:
                extracted_content = att.get("extracted_content")
                if extracted_content:
                    file_name = att.get("file_name", "unknown.csv")
                    print(f"[DEBUG Claude] extracted_content 발견했지만 프롬프트와 함께 처리됨: {file_name}")
                    # CSV는 completion 요청에 포함되므로 file_id 반환하지 않음
                    # 프롬프트 추출 단계에서 함께 처리
                    return None

            return None

        except Exception as e:
            logging.error(f"[Claude] extracted_content 확인 중 오류: {e}")
            import traceback
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