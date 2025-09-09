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
        # 호스트 목록을 문자열로 변환
        hosts_str = "{\n"
        for host in self.LLM_HOSTS:
            hosts_str += f'            "{host}",\n'
        hosts_str += "        }"
        
        script_content = f'''
import json
import urllib.parse
from pathlib import Path
from datetime import datetime
from mitmproxy import http

class LLMSelectiveLogger:
    def __init__(self):
        self.json_log_file = Path.home() / ".llm_proxy" / "llm_requests.json"
        self.LLM_HOSTS = {hosts_str}

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """요청 호스트가 지정된 LLM 목록에 있는지 확인"""
        return flow.request.pretty_host in self.LLM_HOSTS

    def parse_gemini_prompt(self, request_body: str) -> str:
        """Gemini 요청 본문에서 사용자 프롬프트를 파싱하는 함수"""
        try:
            # 1. URL 디코딩을 수행하여 "f.req=..." 부분을 찾습니다.
            decoded_body = urllib.parse.unquote_plus(request_body)
            
            # 2. f.req= 뒤의 JSON 문자열을 추출합니다.
            # f.req= 로 시작하는 부분을 찾아 그 이후의 문자열을 가져옵니다.
            freq_part = decoded_body.split('f.req=', 1)[1]
            
            # 3. 추출된 JSON 문자열을 파싱합니다.
            # 때때로 뒤에 & 같은 다른 파라미터가 붙을 수 있으므로 처리합니다.
            if '&' in freq_part:
                json_str = freq_part.split('&', 1)[0]
            else:
                json_str = freq_part
                
            data = json.loads(json_str)
            
            # 4. JSON 구조를 따라 프롬프트가 있는 곳까지 찾아 들어갑니다.
            # [[["-p_123456...", ["Your Prompt Here", ...], ...]]]
            prompt = data[0][0][1][1][0]
            return prompt
        except (IndexError, KeyError, json.JSONDecodeError, TypeError):
            # 파싱에 실패하면 "파싱 실패"를 반환
            return "프롬프트 파싱 실패"

    def response(self, flow: http.HTTPFlow):
        """응답이 완료되었을 때 LLM 요청인지 확인하고 로깅"""
        if not self.is_llm_request(flow) or not flow.response or not flow.response.content:
            return
        
        # Gemini 요청의 경우, 특별히 프롬프트를 파싱합니다.
        if flow.request.pretty_host == "gemini.google.com" and "batchexecute" in flow.request.path:
            prompt = self.parse_gemini_prompt(flow.request.content.decode(errors='ignore'))
        else:
            prompt = "프롬프트 추출 로직 미구현"

        log_entry = {{
            "timestamp": datetime.now().isoformat(),
            "host": flow.request.pretty_host,
            "prompt": prompt, # 파싱된 프롬프트를 로그에 추가
            "request_body_full": "Non-JSON or empty body", # 전체 본문도 따로 저장
            "response_body": "Non-JSON or empty body"
        }}

        try:
            log_entry["request_body_full"] = json.loads(flow.request.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["request_body_full"] = flow.request.content.decode(errors='ignore')

        try:
            log_entry["response_body"] = json.loads(flow.response.content.decode(errors='ignore'))
        except json.JSONDecodeError:
            log_entry["response_body"] = "Non-JSON or empty body"

        with open(self.json_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2) + "\\n,") # , 를 추가하여 JSON 배열처럼 만듬

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