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
        
        # --- 🎯 로깅할 LLM 서비스 호스트 목록 ---
        self.LLM_HOSTS: Set[str] = {
            # OpenAI / ChatGPT
            "api.openai.com",
            # Anthropic / Claude
            "api.anthropic.com",
            # Google / Gemini, Vertex AI
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            # Groq
            "api.groq.com",
            # Cohere
            "api.cohere.ai",
            # DeepSeek
            "api.deepseek.com",
        }

    def create_llm_logger_script(self) -> Path:
        """지정된 LLM 서비스의 통신만 로깅하는 mitmproxy 스크립트 생성"""
        # 호스트 목록을 문자열로 변환
        hosts_str = "{\n"
        for host in self.LLM_HOSTS:
            hosts_str += f'            "{host}",\n'
        hosts_str += "        }"
        
        script_content = f'''
import json
from pathlib import Path
from datetime import datetime
from mitmproxy import http

class LLMSelectiveLogger:
    def __init__(self):
        self.json_log_file = Path.home() / ".llm_proxy" / "llm_requests.json"
        
        # --- 🎯 로깅할 LLM 서비스 호스트 목록 ---
        self.LLM_HOSTS = {hosts_str}

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """요청 호스트가 지정된 LLM 목록에 있는지 확인"""
        return flow.request.pretty_host in self.LLM_HOSTS

    def response(self, flow: http.HTTPFlow):
        """응답이 완료되었을 때 LLM 요청인지 확인하고 로깅"""
        if not self.is_llm_request(flow) or not flow.response or not flow.response.content:
            return
        
        print(f"✅ LLM API 감지: {{flow.request.pretty_host}}")

        log_entry = {{
            "timestamp": datetime.now().isoformat(),
            "host": flow.request.pretty_host,
            "url": flow.request.pretty_url,
        }}

        try:
            log_entry["request_body"] = json.loads(flow.request.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["request_body"] = "Non-JSON or empty body"

        try:
            log_entry["response_body"] = json.loads(flow.response.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["response_body"] = "Non-JSON or empty body"

        with open(self.json_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2) + "\\n")

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