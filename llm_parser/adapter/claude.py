from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from typing import Optional, Dict, Any, List, Tuple
import json
import base64

# -------------------------------
# Claude Adapter
# -------------------------------
class ClaudeAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Claude/Anthropic API 프롬프트 추출"""
        try:
            # Claude.ai 웹 인터페이스 - prompt 키 직접 확인
            prompt = request_json.get("prompt")
            if prompt and isinstance(prompt, str):
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

    # def extract_attachments(self, request_json: dict, host: str) -> List[Dict[str, Any]]:
        
        
    #     """Claude 첨부파일 추출 - Claude.ai 웹 인터페이스용"""
    #     try:

    #         print(f"[DEBUG] 전체 request_json 키들: {list(request_json.keys())}")
    #         print(f"[DEBUG] prompt 길이: {len(request_json.get('prompt', ''))}")
        
    #         # prompt 일부 출력 (base64 확인용)
    #         prompt = request_json.get("prompt", "")
    #         if len(prompt) > 1000:
    #             print(f"[DEBUG] prompt 앞부분: {prompt[:200]}...")
    #             print(f"[DEBUG] prompt 뒷부분: ...{prompt[-200:]}")
    #             attachments = []
            
    #         # 방법 1: files 배열에서 파일 ID 확인 (Claude.ai 웹)
    #         files = request_json.get("files", [])
    #         if isinstance(files, list) and files:
    #             print(f"[DEBUG] Claude files 감지: {files}")
    #             # 파일 ID만 있고 실제 데이터는 prompt에 포함되어 있을 것임
    #             # 이 경우 prompt에서 base64 이미지를 찾아야 함
    #             prompt = request_json.get("prompt", "")
    #             if prompt:
    #                 # prompt에서 base64 이미지 데이터 추출 시도
    #                 base64_images = self._extract_base64_from_prompt(prompt)
    #                 for i, base64_data in enumerate(base64_images):
    #                     attachments.append({
    #                         "type": "base64",
    #                         "data": base64_data,
    #                         "format": "image/unknown",  # 정확한 포맷은 base64 헤더에서 추출 가능
    #                         "file_id": files[i] if i < len(files) else f"unknown_{i}"
    #                     })
            
    #         # 방법 2: messages에서 이미지 컨텐츠 찾기 (Anthropic API)
    #         messages = request_json.get("messages", [])
    #         if isinstance(messages, list):
    #             for message in messages:
    #                 if isinstance(message, dict) and message.get("role") == "user":
    #                     content = message.get("content")
                        
    #                     # content가 배열인 경우 (multimodal)
    #                     if isinstance(content, list):
    #                         for part in content:
    #                             if isinstance(part, dict) and part.get("type") == "image":
    #                                 source = part.get("source", {})
    #                                 if source.get("type") == "base64":
    #                                     base64_data = source.get("data")
    #                                     if base64_data:
    #                                         attachments.append({
    #                                             "type": "base64", 
    #                                             "data": base64_data,
    #                                             "format": source.get("media_type", "image/unknown")
    #                                         })
            
    #         # 방법 3: attachments 배열 확인
    #         request_attachments = request_json.get("attachments", [])
    #         if isinstance(request_attachments, list):
    #             for attachment in request_attachments:
    #                 if isinstance(attachment, dict):
    #                     # 첨부파일 구조에 따라 처리
    #                     if "data" in attachment:
    #                         attachments.append({
    #                             "type": "base64",
    #                             "data": attachment["data"],
    #                             "format": attachment.get("type", "image/unknown")
    #                         })
            
    #         if attachments:
    #             print(f"[DEBUG] Claude 첨부파일 {len(attachments)}개 추출 완료")
            
    #         return attachments
            
    #     except Exception as e:
    #         print(f"[DEBUG] Claude 첨부파일 추출 실패: {e}")
    #         return []

    # def _extract_base64_from_prompt(self, prompt: str) -> List[str]:
    #     """프롬프트에서 base64 이미지 데이터 추출"""
    #     try:
    #         base64_images = []
            
    #         # 일반적인 base64 이미지 패턴들 검색
    #         import re
            
    #         # data:image/[type];base64,[data] 패턴
    #         data_uri_pattern = r'data:image/[^;]+;base64,([A-Za-z0-9+/=]+)'
    #         matches = re.findall(data_uri_pattern, prompt)
    #         base64_images.extend(matches)
            
    #         # 순수 base64 데이터 패턴 (최소 100자 이상의 base64 문자열)
    #         pure_base64_pattern = r'([A-Za-z0-9+/]{100,}={0,2})'
    #         pure_matches = re.findall(pure_base64_pattern, prompt)
            
    #         # base64 검증
    #         for match in pure_matches:
    #             try:
    #                 # base64 디코딩 테스트
    #                 decoded = base64.b64decode(match + '==')  # 패딩 추가
    #                 # 이미지 매직 넘버 확인
    #                 if (decoded.startswith(b'\xFF\xD8\xFF') or  # JPEG
    #                     decoded.startswith(b'\x89PNG') or      # PNG
    #                     decoded.startswith(b'GIF8') or         # GIF
    #                     decoded.startswith(b'RIFF')):          # WebP
    #                     base64_images.append(match)
    #             except:
    #                 continue
            
    #         return base64_images
            
    #     except Exception as e:
    #         print(f"[DEBUG] base64 추출 실패: {e}")
    #         return []

    # def is_file_download_request(self, flow: http.HTTPFlow) -> bool:
    #     """Claude는 파일 다운로드가 아닌 직접 전송 방식이므로 False 반환"""
    #     return False

    # def extract_file_info(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
    #     """Claude는 파일 다운로드가 아닌 직접 전송 방식이므로 None 반환"""
    #     return None