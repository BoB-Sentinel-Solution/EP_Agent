#!/usr/bin/env python3
"""
파일 다운로더 - LLM 파일/이미지 추출 및 저장
"""

import json
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from mitmproxy import http


class FileDownloadUtils:
    """공통 유틸리티 함수들"""
    
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        """지원하는 파일 타입인지 확인"""
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types
    
    @staticmethod
    def safe_filename(original_name: str, file_id: str = None) -> str:
        """안전한 파일명 생성"""
        import re
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        
        # 특수문자 제거
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:30]
        
        return f"{timestamp}_{safe_stem}{ext}"


class ChatGPTFileExtractor:
    """ChatGPT 파일 추출기"""
    
    def can_handle(self, flow: http.HTTPFlow) -> bool:
        """ChatGPT 파일 요청인지 확인"""
        return (
            "chatgpt.com" in flow.request.pretty_host and
            "/backend-api/files/download/" in flow.request.path and
            flow.request.method == "GET"
        )

    def extract_file_info(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """파일 정보 추출"""
        try:
            if flow.response.status_code != 200:
                return None
            
            response_data = json.loads(flow.response.get_text())
            
            if response_data.get("status") != "success":
                return None
            
            download_url = response_data.get("download_url")
            file_name = response_data.get("file_name")
            
            if not download_url or not file_name:
                return None
            
            if not FileDownloadUtils.is_supported_file(file_name):
                return None
            
            return {
                "download_url": download_url,
                "file_name": file_name,
                "headers": dict(flow.request.headers)
            }
            
        except Exception:
            return None


class LLMFileDownloader:
    """LLM 파일 다운로더 - mitmproxy 애드온"""
    
    def __init__(self):
        self.download_dir = Path.home() / ".llm_proxy" / "downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)
        
        # LLM별 추출기 등록
        self.extractors = [
            ChatGPTFileExtractor(),
            # 나중에 다른 LLM 추출기 추가 가능
        ]
        
    def response(self, flow: http.HTTPFlow):
        """파일 다운로드 감지 및 처리"""
        try:
            for extractor in self.extractors:
                if extractor.can_handle(flow):
                    file_info = extractor.extract_file_info(flow)
                    
                    if file_info:
                        self.download_file(file_info)
                    break
                        
        except Exception as e:
            print(f"[ERROR] 파일 처리 실패: {e}")

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
            safe_name = FileDownloadUtils.safe_filename(file_name)
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


# mitmproxy 애드온 등록
addons = [LLMFileDownloader()]