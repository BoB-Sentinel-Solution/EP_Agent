#!/usr/bin/env python3
"""
LLM 트래픽 파서 - 텍스트 프롬프트와 파일 다운로드 통합 처리
"""
import json
import requests
import urllib.parse
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Optional, Dict, Any, List
import re

# -------------------------------
# 공통 유틸리티
# -------------------------------
class FileUtils:
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        """지원하는 파일 타입인지 확인"""
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types
    
    @staticmethod
    def safe_filename(original_name: str) -> str:
        """안전한 파일명 생성"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        
        # 특수문자 제거
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:30]
        return f"{timestamp}_{safe_stem}{ext}"

# -------------------------------
# Adapter 인터페이스 (확장됨)
# -------------------------------
class LLMAdapter:
    """LLM Adapter 기본 인터페이스"""
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        raise NotImplementedError
    
    def extract_attachments(self, request_json: dict, host: str) -> list:
        """첨부파일 정보 추출 (기본 구현은 빈 리스트)"""
        return []
    
    def extract_file_info(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 다운로드 정보 추출 (기본 구현은 None)"""
        return None
    
    def is_file_download_request(self, flow: http.HTTPFlow) -> bool:
        """파일 다운로드 요청인지 확인"""
        return False

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

# -------------------------------
# Claude Adapter
# -------------------------------
class ClaudeAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Claude/Anthropic API 프롬프트 추출"""
        try:
            # 직접 prompt 키 확인
            prompt = request_json.get("prompt")
            if prompt and isinstance(prompt, str):
                return prompt[:1000]
            
            # messages 패턴 확인
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    content = last_message.get("content")
                    if content and isinstance(content, str):
                        return content[:1000]
            
            return None
        except Exception:
            return None

# -------------------------------
# Gemini Adapter
# -------------------------------
class GeminiAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """Google Gemini API 프롬프트 추출"""
        try:
            # contents 패턴 처리
            contents = request_json.get("contents", [])
            if contents and isinstance(contents, list):
                last_content = contents[-1]
                if isinstance(last_content, dict):
                    parts = last_content.get("parts", [])
                    if parts and isinstance(parts, list):
                        for part in parts:
                            if isinstance(part, dict):
                                text_part = part.get("text")
                                if text_part:
                                    return text_part[:1000]
            
            # 기본 prompt 키 확인
            prompt = request_json.get("prompt")
            if prompt:
                return str(prompt)[:1000]
                
            return None
        except Exception:
            return None

# -------------------------------
# Generic Adapter
# -------------------------------
class GenericAdapter(LLMAdapter):
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        """기타 LLM API들을 위한 일반적인 프롬프트 추출"""
        try:
            # 일반적인 키들을 순서대로 확인
            for key in ["prompt", "input", "text", "message", "query"]:
                value = request_json.get(key)
                if value:
                    return str(value)[:1000]
            
            # messages 패턴 확인
            messages = request_json.get("messages", [])
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    content = last_message.get("content")
                    if content:
                        return str(content)[:1000]
            
            return None
        except Exception:
            return None

# -------------------------------
# 통합 LLM Logger
# -------------------------------
class UnifiedLLMLogger:
    def __init__(self):
        self.base_dir = Path.home() / ".llm_proxy"
        self.json_log_file = self.base_dir / "llm_requests.json"
        self.download_dir = self.base_dir / "downloads"
        
        # 디렉토리 생성
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        
        # LLM 호스트 목록
        self.LLM_HOSTS = {
            "api.openai.com", "chatgpt.com",
            "api.anthropic.com", "claude.ai", 
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com", "gemini.google.com",
            "api.groq.com", "api.cohere.ai", "api.deepseek.com",
        }
        
        # 호스트별 어댑터 매핑
        self.adapters: Dict[str, LLMAdapter] = {
            "chatgpt.com": ChatGPTAdapter(),
            "api.openai.com": GenericAdapter(),
            "claude.ai": ChatGPTAdapter(),
            "api.anthropic.com": ClaudeAdapter(),
            "gemini.google.com": GeminiAdapter(),
            "generativelanguage.googleapis.com": GeminiAdapter(),
            "aiplatform.googleapis.com": GeminiAdapter(),
        }
        
        # 기본 어댑터
        self.default_adapter = GenericAdapter()

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """요청 호스트가 지정된 LLM 목록에 있는지 확인"""
        return flow.request.pretty_host in self.LLM_HOSTS

    def get_adapter(self, host: str) -> LLMAdapter:
        """호스트에 맞는 어댑터를 반환"""
        for adapter_host, adapter in self.adapters.items():
            if adapter_host in host:
                return adapter
        return self.default_adapter

    def safe_decode_content(self, content: bytes) -> str:
        """바이트 컨텐츠를 안전하게 디코딩"""
        if not content:
            return ""
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return f"[BINARY_CONTENT: {len(content)} bytes]"

    def parse_json_safely(self, content: str) -> dict:
        """JSON을 안전하게 파싱"""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}

    def download_file(self, file_info: Dict[str, Any]) -> Optional[Path]:
        """파일 다운로드 및 저장"""
        try:
            download_url = file_info["download_url"]
            file_name = file_info["file_name"]
            headers = file_info["headers"]
            
            print(f"[DOWNLOAD] {file_name}")
            
            # 다운로드
            response = requests.get(download_url, headers={
                "User-Agent": headers.get("user-agent", ""),
                "Authorization": headers.get("authorization", ""),
                "Cookie": headers.get("cookie", "")
            }, stream=True, timeout=30)
            
            response.raise_for_status()
            
            # 파일 저장
            safe_name = FileUtils.safe_filename(file_name)
            file_path = self.download_dir / safe_name
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            print(f"[SUCCESS] 저장완료: {file_path}")
            return file_path
            
        except Exception as e:
            print(f"[ERROR] 다운로드 실패: {e}")
            return None

    def save_log(self, log_entry: Dict[str, Any]):
        """로그 항목 저장"""
        try:
            logs = []
            if self.json_log_file.exists():
                try:
                    with open(self.json_log_file, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                        if content and content.startswith('['):
                            logs = json.loads(content)
                        else:
                            print(f"[WARN] 로그 파일 형식이 올바르지 않아 초기화합니다: {self.json_log_file}")
                except Exception:
                    logs = []
            
            logs.append(log_entry)
            
            if len(logs) > 100:
                logs = logs[-100:]
            
            with open(self.json_log_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"[ERROR] 로그 저장 실패: {e}")

    def request(self, flow: http.HTTPFlow):
        """POST 요청 처리 - 프롬프트 추출"""
        if not self.is_llm_request(flow) or flow.request.method != 'POST':
            return

        host = flow.request.pretty_host
        request_body = self.safe_decode_content(flow.request.content)
        request_json = self.parse_json_safely(request_body)

        if not request_json:
            return
        
        # 적절한 어댑터를 사용하여 프롬프트 추출
        adapter = self.get_adapter(host)
        prompt = adapter.extract_prompt(request_json, host)
        attachments = adapter.extract_attachments(request_json, host)

        # 프롬프트가 있거나 첨부파일이 있는 경우에만 로그 기록
        if prompt or attachments:
            log_entry = {
                "time": datetime.now().isoformat(),
                "host": host,
                "prompt": prompt if prompt is not None else "",
                "attachments": attachments,
                "interface": "llm"
            }

            self.save_log(log_entry)
            display_text = (prompt[:80] if prompt else "[첨부파일]") + "..."
            print(f"[LOG] {host} - {display_text}")

    def response(self, flow: http.HTTPFlow):
        """응답 처리 - 파일 다운로드만 처리"""
        if not self.is_llm_request(flow):
            return
            
        try:
            host = flow.request.pretty_host
            adapter = self.get_adapter(host)
            
            # 파일 다운로드 요청인지 확인하고 처리
            if adapter.is_file_download_request(flow):
                file_info = adapter.extract_file_info(flow)
                
                if file_info:
                    self.download_file(file_info)  # host 인자 제거
                        
        except Exception as e:
            print(f"[ERROR] 응답 처리 실패: {e}")

# -------------------------------
# mitmproxy 애드온 등록
# -------------------------------
addons = [UnifiedLLMLogger()]