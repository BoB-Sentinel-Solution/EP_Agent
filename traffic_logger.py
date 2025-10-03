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
            "api.groq.com", "groq.com",
            # Cohere
            "api.cohere.ai",
            # DeepSeek
            "api.deepseek.com","chat.deepseek.com"

        }
        

        # 2. 와일드카드 패턴 목록 ('*.cursor.sh'는 '.cursor.sh'로 끝나는지 확인)
        self.LLM_HOST_PATTERNS: Set[str] = {
            ".cursor.sh"
        }

        # 설정 파일에서 호스트 목록 로드
        self.load_hosts_config()

    def get_script_file_path(self) -> str:
        """
        mitmproxy에 전달할 스크립트 파일의 절대 경로를 반환합니다.
        mitmdump는 실제 파일 경로가 필요하므로 파일의 절대 경로를 반환합니다.
        """
        
        
        script_file = self.project_root / "llm_parser" / "llm_main.py"
        #script_file = self.project_root / "debugging_all.py"

        # 파일이 존재하는지 확인
        if not script_file.exists():
            raise FileNotFoundError(f"스크립트 파일이 존재하지 않습니다: {script_file}")
        
        # 절대 경로로 변환하여 반환
        absolute_path = script_file.resolve()
        print(f"[INFO] 사용할 스크립트 파일: {absolute_path}")
        
        return str(absolute_path)


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

        
    def get_llm_hosts(self) -> Set[str]:
        """현재 등록된 LLM 호스트 목록 반환"""
        return self.LLM_HOSTS.copy()

    def get_all_monitored_hosts(self) -> Set[str]:
        """
        LLM_HOSTS + 패턴 기반 호스트들을 모두 포함한 전체 감시 대상 호스트 반환
        (mitmproxy --allow-hosts 옵션용)
        """
        all_hosts = self.LLM_HOSTS.copy()

        # 패턴 호스트들을 실제 도메인으로 변환
        for pattern in self.LLM_HOST_PATTERNS:
            if pattern.startswith('.'):
                # '.cursor.sh' -> 'cursor.sh' (서브도메인 포함 매칭은 mitmproxy에서 처리)
                all_hosts.add(pattern.lstrip('.'))

        return all_hosts
    
    def is_llm_host(self, host: str) -> bool:
        """
        주어진 호스트가 지정된 LLM 서비스 호스트인지 확인합니다.
        (정확한 일치와 패턴 일치를 모두 검사)
        """
        # 1. 정확히 일치하는지 먼저 확인 (가장 빠름)
        if host in self.LLM_HOSTS:
            return True

        # 2. 패턴으로 끝나는지 확인
        for pattern in self.LLM_HOST_PATTERNS:
            if host.endswith(pattern):
                return True
        
        return False