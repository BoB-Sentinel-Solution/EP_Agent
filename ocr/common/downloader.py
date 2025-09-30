#!/usr/bin/env python3
"""
파일 저장 모듈

가로챈 파일 데이터를 로컬에 저장하고 메타데이터를 관리합니다.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import logging

from .file_utils import FileUtils

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileDownloader:
    """파일 저장 전용 클래스"""

    def __init__(self, temp_dir: Path = None):
        # 다운로드 폴더 구조 설정
        self.downloads_dir = Path.home() / ".llm_proxy" / "downloads"
        self.intercepted_dir = self.downloads_dir / "intercepted"
        self.metadata_dir = self.downloads_dir / "metadata"

        # 폴더들 생성
        for directory in [self.downloads_dir, self.intercepted_dir, self.metadata_dir]:
            directory.mkdir(parents=True, exist_ok=True)



    def _get_extension_from_content_type(self, content_type: str) -> str:
        """Content-Type에서 파일 확장자 추출"""
        type_to_ext = {
            "image/jpeg": ".jpg",
            "image/jpg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
            "image/bmp": ".bmp",
            "image/tiff": ".tiff",
            "image/webp": ".webp",
            "application/pdf": ".pdf",
            "text/plain": ".txt"
        }

        for content_type_key, extension in type_to_ext.items():
            if content_type_key in content_type.lower():
                return extension

        return ".tmp"  # 기본 확장자





    def save_intercepted_file(self,
                            file_data: bytes,
                            original_url: str,
                            host: str,
                            content_type: str = None,
                            method: str = "UNKNOWN",
                            additional_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        가로챈 파일을 다운로드 폴더에 저장

        Args:
            file_data: 파일 바이너리 데이터
            original_url: 원본 업로드 URL
            host: 호스트명 (예: files.oaiusercontent.com)
            content_type: Content-Type 헤더
            method: HTTP 메서드 (PUT, POST 등)
            additional_info: 추가 정보

        Returns:
            저장 결과 정보
        """
        try:
            # 1. 안전한 파일명 생성
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            url_hash = hashlib.md5(original_url.encode()).hexdigest()[:8]

            # 확장자 결정
            extension = self._get_extension_from_content_type(content_type or "")
            filename = f"intercepted_{timestamp}_{url_hash}{extension}"

            # 2. 파일 저장
            file_path = self.intercepted_dir / filename
            file_path.write_bytes(file_data)

            # 3. 파일 정보 계산
            file_size = len(file_data)
            file_hash = hashlib.sha256(file_data).hexdigest()

            # 4. 메타데이터 생성
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "file_path": str(file_path),
                "file_size": file_size,
                "file_hash": file_hash,
                "original_url": original_url,
                "host": host,
                "content_type": content_type,
                "http_method": method,
                "source": "intercepted_upload"
            }

            # 추가 정보 병합
            if additional_info:
                metadata.update(additional_info)

            # 5. 메타데이터 파일 저장
            metadata_filename = f"{filename}.metadata.json"
            metadata_path = self.metadata_dir / metadata_filename
            metadata_path.write_text(
                json.dumps(metadata, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

            logging.info(f"[SAVE] 파일 저장 완료: {filename} ({file_size} bytes) -> {self.intercepted_dir}")

            return {
                "success": True,
                "filename": filename,
                "file_path": str(file_path),
                "metadata_path": str(metadata_path),
                "file_size": file_size,
                "file_hash": file_hash
            }

        except Exception as e:
            logging.error(f"[SAVE] 파일 저장 실패: {e}")
            return {
                "success": False,
                "error": str(e)
            }

