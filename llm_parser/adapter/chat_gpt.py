from llm_parser.common.utils import LLMAdapter, FileUtils
from mitmproxy import http
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import os
import json
import logging
import base64

UNIFIED_LOG_PATH = "./unified_request.json"

# -------------------------------
# ChatGPT Adapter (통합됨)
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def _save_unified_log(self, data: dict):
        """unified_request.json에 로그 append"""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(UNIFIED_LOG_PATH)) or ".", exist_ok=True)
            with open(UNIFIED_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[ERROR] unified_request.json 기록 실패: {e}")

    
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        try:
            messages = request_json.get("messages", [])
            if not isinstance(messages, list) or not messages:
                return None

            last_message = messages[-1]
            author = last_message.get("author", {})
            role = author.get("role")
            name = author.get("name")

            # --- Case 1: user role ---
            if role == "user":
                # system_hints 체크 (agent 있으면 MCP, 없으면 LLM)
                metadata = last_message.get("metadata", {})
                system_hints = metadata.get("system_hints", [])

                has_agent = False
                if isinstance(system_hints, list):
                    has_agent = "agent" in system_hints
                elif isinstance(system_hints, str):
                    has_agent = "agent" in system_hints

                # 프롬프트 추출
                content = last_message.get("content", {})
                parts = content.get("parts", [])
                text = content.get("text")

                extracted_prompt = None
                if parts and isinstance(parts, list):
                    text_parts_list = []
                    for part in parts:
                        if isinstance(part, str):
                            text_parts_list.append(part)
                        elif isinstance(part, dict) and part.get("content_type") == "text":
                            text_parts_list.append(part.get("content", ""))
                    if text_parts_list:
                        extracted_prompt = " ".join(text_parts_list)[:1000]
                        print(f"[DEBUG ChatGPTAdapter] user role 프롬프트 추출: {extracted_prompt[:50]}...")

                if not extracted_prompt and text and isinstance(text, str):
                    extracted_prompt = text[:1000]
                    print(f"[DEBUG ChatGPTAdapter] user role text 추출: {extracted_prompt[:50]}...")

                # --- [!!!] 핵심 수정 지점 ---
                if extracted_prompt:
                    interface = "mcp" if has_agent else "llm"
                    
                    # [수정] 로그를 직접 저장하는 대신,
                    # 상위 로거(llm_main.py)가 처리할 dict를 반환합니다.
                    result = {
                        "prompt": extracted_prompt,
                        # llm_main.py가 attachment를 기대할 수 있으므로 호환성을 위해 추가
                        "attachment": {"format": None, "data": None}, 
                        "interface": interface
                    }
                    print(f"[DEBUG ChatGPTAdapter] 프롬프트 추출 완료 (interface={interface}): {extracted_prompt[:50]}...")
                    # [수정] 문자열이 아닌 dict(result)를 반환
                    return result 
                
                # [수정] 프롬프트가 없는 경우
                return None

            # --- Case 2: 기타 ---
            print(f"[DEBUG ChatGPTAdapter] role={role}, name={name} => 프롬프트 추출 대상 아님")
            return None

        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
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
            
            
            # [수정] GPT-4o 등 parts가 dict일 경우도 처리
            if parts:
                if isinstance(parts[0], str):
                    request_data["messages"][-1]["content"]["parts"][0] = modified_prompt
                    modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes
                elif isinstance(parts[0], dict) and parts[0].get("content_type") == "text":
                    request_data["messages"][-1]["content"]["parts"][0]["content"] = modified_prompt
                    modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes

            # [수정] 'text' 필드만 있는 경우
            elif "text" in content:
                request_data["messages"][-1]["content"]["text"] = modified_prompt
                modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                return True, modified_bytes

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


