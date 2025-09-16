from llm_parser.common.utils import LLMAdapter, FileUtils 
from mitmproxy import http
from typing import Optional, Dict, Any
import json
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

    def is_file_download_request(self, flow: http.HTTPFlow) -> bool:
        """ChatGPT 파일 다운로드 요청인지 확인"""
        return (
            "chatgpt.com" in flow.request.pretty_host and
            "/backend-api/files/download/" in flow.request.path and
            flow.request.method == "GET"
        )

    def extract_file_info(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """ChatGPT 파일 정보 추출"""
        if not self.is_file_download_request(flow):
            return None
            
        try:
            print(f"[DEBUG] Response status: {flow.response.status_code}")
            
            if flow.response.status_code != 200:
                print(f"[DEBUG] 응답 상태 코드가 200이 아님: {flow.response.status_code}")
                return None
            
            response_text = flow.response.get_text()
            print(f"[DEBUG] Response body: {response_text[:200]}...")
            
            response_data = json.loads(response_text)
            print(f"[DEBUG] Parsed JSON: {response_data}")
            
            if response_data.get("status") != "success":
                print(f"[DEBUG] 응답 상태가 success가 아님: {response_data.get('status')}")
                return None
            
            download_url = response_data.get("download_url")
            file_name = response_data.get("file_name")
            
            print(f"[DEBUG] Download URL: {download_url}")
            print(f"[DEBUG] File name: {file_name}")
            
            if not download_url or not file_name:
                print(f"[DEBUG] download_url 또는 file_name이 없음")
                return None
            
            if not FileUtils.is_supported_file(file_name):
                print(f"[DEBUG] 지원하지 않는 파일 형식: {file_name}")
                return None
            
            return {
                "download_url": download_url,
                "file_name": file_name,
                "headers": dict(flow.request.headers)
            }
            
        except json.JSONDecodeError as e:
            print(f"[DEBUG] JSON 파싱 실패: {e}")
            return None
        except Exception as e:
            print(f"[DEBUG] 파일 정보 추출 중 오류: {e}")
            return None
