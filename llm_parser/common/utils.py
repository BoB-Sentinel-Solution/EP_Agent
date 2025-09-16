# D:\Sentinel_Project\EP_Agent\llm_parser\common\utils.py

from typing import Optional, Dict, Any
from mitmproxy import http

# llm_main.py에 있던 LLMAdapter 베이스 클래스를 이곳으로 이동
class LLMAdapter:
    """LLM Adapter 기본 인터페이스"""
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        raise NotImplementedError("extract_prompt가 구현되지 않았습니다.")

    def extract_attachments(self, request_json: dict, host: str) -> list:
        return []

    def extract_file_info(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        return None

    def is_file_download_request(self, flow: http.HTTPFlow) -> bool:
        return False

# 만약 다른 공통 함수(FileUtils 등)가 있다면 그것도 이 파일로 옮기는 것이 좋습니다.