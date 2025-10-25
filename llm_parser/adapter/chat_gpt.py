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
        """ChatGPT 요청 데이터 변조"""
        try:
            # JSON 구조 확인
            messages = request_data.get("messages", [])
            if not messages:
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})
            if author.get("role") != "user":
                return False, None

            # 프롬프트 변조
            content = last_message.get("content", {})
            parts = content.get("parts", [])
            if parts and isinstance(parts[0], str):
                request_data['messages'][-1]['content']['parts'][0] = modified_prompt

                # 바이너리 변환
                modified_content = json.dumps(request_data, ensure_ascii=False).encode('utf-8')
                return True, modified_content

            return False, None
        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None



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


