from typing import Optional, Dict, Any
from mitmproxy import http
from pathlib import Path
from datetime import datetime
import re

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


class FileUtils:
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types

    @staticmethod
    def safe_filename(original_name: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:30]
        return f"{timestamp}_{safe_stem}{ext}"