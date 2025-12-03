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

    # 파일 처리는 claude_file_handler.py로 이동됨
    # extract_file_from_upload_request는 호환성을 위해 유지하되, 핸들러로 위임
    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 처리는 claude_file_handler.py에서 담당

        이 메서드는 llm_main.py 호환성을 위해 유지되며,
        실제 파일 변조는 dispatcher에서 claude_file_handler를 통해 처리됩니다.
        """
        # 파일 업로드 요청 여부만 확인
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path

        if not ("claude.ai" in host or "api.anthropic.com" in host):
            return None

        # POST /upload 또는 /convert_document (multipart) 확인
        if method == "POST" and ("/upload" in path or "/convert_document" in path):
            content_type = flow.request.headers.get("content-type", "").lower()
            if "multipart/form-data" in content_type:
                # 파일 업로드 요청임을 표시 (실제 처리는 핸들러에서)
                return {"file_upload_detected": True}

        return None