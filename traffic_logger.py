#!/usr/bin/env python3
"""
트래픽 로거 - LLM API 트래픽 감지 및 로깅 설정 관리
"""

from pathlib import Path
from typing import Set
import json


class TrafficLogger:
    """LLM 트래픽 로깅 설정을 담당하는 클래스"""
    
    def __init__(self, app_dir: Path, project_root: Path):
        self.app_dir = app_dir
        self.project_root = project_root
        self.json_log_file = app_dir / "llm_requests.json"
        self.config_file = app_dir / "llm_hosts_config.json"
        
        # --- 로깅할 LLM 서비스 호스트 목록 ---
        self.LLM_HOSTS: Set[str] = {
            # OpenAI / ChatGPT
            "api.openai.com", "chatgpt.com",
            # Anthropic / Claude
            "api.anthropic.com", "claude.ai",
            # Google / Gemini, Vertex AI
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com", "gemini.google.com",
            # Groq
            "api.groq.com",
            # Cohere
            "api.cohere.ai",
            # DeepSeek
            "api.deepseek.com",
        }
        
        # 설정 파일에서 호스트 목록 로드
        self.load_hosts_config()

    def get_script_file_path(self) -> str:
        """
        mitmproxy에 전달할 스크립트 파일의 절대 경로를 반환합니다.
        mitmdump는 실제 파일 경로가 필요하므로 파일의 절대 경로를 반환합니다.
        """
        script_file = self.project_root / "llm_parser" / "llm_main.py"
        
        # 파일이 존재하는지 확인
        if not script_file.exists():
            raise FileNotFoundError(f"스크립트 파일이 존재하지 않습니다: {script_file}")
        
        # 절대 경로로 변환하여 반환
        absolute_path = script_file.resolve()
        print(f"[INFO] 사용할 스크립트 파일: {absolute_path}")
        
        return str(absolute_path)

    def get_script_module_path(self) -> str:
        """
        DEPRECATED: 이 메서드는 더 이상 사용하지 않습니다.
        대신 get_script_file_path()를 사용하세요.
        """
        print("[WARN] get_script_module_path()는 deprecated입니다. get_script_file_path()를 사용하세요.")
        return self.get_script_file_path()

    def load_hosts_config(self):
        """설정 파일에서 LLM 호스트 목록을 로드"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.LLM_HOSTS = set(config.get('llm_hosts', list(self.LLM_HOSTS)))
            except Exception as e:
                print(f"[WARN] 설정 파일 로드 실패, 기본값 사용: {e}")

    def save_hosts_config(self):
        """현재 LLM 호스트 목록을 설정 파일에 저장"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            config = {'llm_hosts': list(self.LLM_HOSTS)}
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ERROR] 설정 파일 저장 실패: {e}")

    def add_llm_host(self, host: str):
        """새로운 LLM 호스트를 추가"""
        self.LLM_HOSTS.add(host)
        self.save_hosts_config()
        
    def remove_llm_host(self, host: str):
        """LLM 호스트를 제거"""
        self.LLM_HOSTS.discard(host)
        self.save_hosts_config()
        
    def get_llm_hosts(self) -> Set[str]:
        """현재 등록된 LLM 호스트 목록 반환"""
        return self.LLM_HOSTS.copy()
    
    def is_llm_host(self, host: str) -> bool:
        """주어진 호스트가 LLM 서비스 호스트인지 확인"""
        return any(llm_host in host for llm_host in self.LLM_HOSTS)