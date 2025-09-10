#!/usr/bin/env python3
"""
트래픽 로거 - LLM API 트래픽 감지 및 로깅 담당
"""

from pathlib import Path
from typing import Set


class TrafficLogger:
    """LLM 트래픽 로깅을 담당하는 클래스"""
    
    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.json_log_file = app_dir / "llm_requests.json"
        
        # --- 로깅할 LLM 서비스 호스트 목록 ---
        self.LLM_HOSTS: Set[str] = {
            # OpenAI / ChatGPT
            "api.openai.com", "chatgpt.com",
            # Anthropic / Claude
            "api.anthropic.com", "claude.ai",
            # Google / Gemini, Vertex AI
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com","gemini.google.com",
            # Groq
            "api.groq.com",
            # Cohere
            "api.cohere.ai",
            # DeepSeek
            "api.deepseek.com",
        }

    def create_llm_logger_script(self) -> Path:
        """지정된 LLM 서비스의 통신만 로깅하는 mitmproxy 스크립트 생성"""
        
        # 호스트 목록을 리스트 형식 문자열로 변환
        hosts_list_str = "[\n"
        for host in self.LLM_HOSTS:
            hosts_list_str += f'    "{host}",\n'
        hosts_list_str += "]"

        script_content = f'''
    import json
    import urllib.parse
    from pathlib import Path
    from datetime import datetime
    from mitmproxy import http
    from typing import List, Dict, Any

    class LLMSelectiveLogger:
        def __init__(self):
            self.json_log_file = Path.home() / ".llm_proxy" / "llm_requests.json"
            # LLM 호스트 목록 (리스트 형식)
            self.LLM_HOSTS = {hosts_list_str}

        def is_llm_request(self, flow: http.HTTPFlow) -> bool:
            return flow.request.pretty_host in self.LLM_HOSTS

        def determine_interface(self, host: str) -> str:
            if host in ["chatgpt.com", "gemini.google.com", "claude.ai"]:
                return "llm"
            elif "api." in host or "googleapis.com" in host:
                return "api"
            else:
                return "unknown"

        def parse_attachments(self, host: str, request_data: Any) -> List[Dict[str, str]]:
            attachments = []
            try:
                if host == "claude.ai" and isinstance(request_data, dict):
                    for attachment in request_data.get("attachments", []):
                        attachments.append({{
                            "type": attachment.get("file_type", "document"),
                            "filename": attachment.get("file_name", "unknown_file")
                        }})
            except Exception:
                pass
            return attachments

        def parse_gemini_prompt(self, request_body: str) -> str:
            try:
                decoded_body = urllib.parse.unquote_plus(request_body)
                freq_part = decoded_body.split('f.req=', 1)[1]
                json_str = freq_part.split('&', 1)[0] if '&' in freq_part else freq_part
                data = json.loads(json_str)
                inner_json_str = data[1]
                inner_data = json.loads(inner_json_str)
                prompt = inner_data[0][0]
                return prompt if isinstance(prompt, str) and len(prompt) > 2 else None
            except Exception:
                try:
                    prompt = json.loads(json.loads(json_str)[0][0][1])[1][0]
                    return prompt if isinstance(prompt, str) and len(prompt) > 2 else None
                except Exception:
                    return None

        def parse_chatgpt_prompt(self, request_data: Dict[str, Any]) -> str:
            try:
                messages = request_data.get("messages", [])
                if messages and messages[-1].get("role") == "user":
                    content_parts = messages[-1].get("content", {{}}).get("parts", [])
                    if content_parts and isinstance(content_parts[0], str):
                        return content_parts[0]
                return None
            except Exception:
                return None

        def parse_claude_prompt(self, request_data: Dict[str, Any]) -> str:
            try:
                prompt = request_data.get("prompt")
                return prompt if prompt and isinstance(prompt, str) else None
            except Exception:
                return None

        def response(self, flow: http.HTTPFlow):
            if not self.is_llm_request(flow) or not flow.response:
                return

            prompt = None
            attachments = []
            host = flow.request.pretty_host
            try:
                request_data = json.loads(flow.request.content.decode(errors='ignore'))
            except json.JSONDecodeError:
                request_data = flow.request.content.decode(errors='ignore')

            if host == "gemini.google.com" and "batchexecute" in flow.request.path and isinstance(request_data, str):
                prompt = self.parse_gemini_prompt(request_data)
            elif host == "chatgpt.com" and "conversation" in flow.request.path and isinstance(request_data, dict):
                prompt = self.parse_chatgpt_prompt(request_data)
            elif host == "claude.ai" and "append_message" in flow.request.path and isinstance(request_data, dict):
                prompt = self.parse_claude_prompt(request_data)
                attachments = self.parse_attachments(host, request_data)
            elif "api." in host or "googleapis.com" in host:
                if isinstance(request_data, dict):
                    prompt = str(request_data.get("messages", request_data.get("prompt", "API 프롬프트 파싱 실패")))

            if prompt:
                log_entry = {{
                    "time": datetime.now().isoformat(),
                    "host": host,
                    "prompt": prompt,
                    "attachments": attachments,
                    "interface": self.determine_interface(host)
                }}
                with open(self.json_log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry, ensure_ascii=False, indent=2) + ",\\n")

    addons = [LLMSelectiveLogger()]
    '''

        script_file = self.app_dir / "llm_logger.py"
        script_file.write_text(script_content, encoding='utf-8')
        return script_file

    def add_llm_host(self, host: str):
        """새로운 LLM 호스트를 추가"""
        self.LLM_HOSTS.add(host)
        
    def remove_llm_host(self, host: str):
        """LLM 호스트를 제거"""
        self.LLM_HOSTS.discard(host)
        
    def get_llm_hosts(self) -> Set[str]:
        """현재 등록된 LLM 호스트 목록 반환"""
        return self.LLM_HOSTS.copy()