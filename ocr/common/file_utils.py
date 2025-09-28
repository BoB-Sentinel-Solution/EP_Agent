#!/usr/bin/env python3
"""
공통 파일 유틸리티 모듈

모든 LLM 프로세서에서 공통으로 사용할 수 있는 파일 관련 유틸리티 기능을 제공합니다.
- 안전한 파일명 생성
- 파일 형식 검증
- 임시 파일 관리
- 파일 정보 추출
"""

import re
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileUtils:
    """파일 관련 유틸리티 클래스"""

    # 지원하는 이미지 파일 확장자
    SUPPORTED_IMAGE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp'
    }

    # 지원하는 Content-Type
    SUPPORTED_CONTENT_TYPES = {
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
        'image/bmp', 'image/tiff', 'image/webp'
    }

    @staticmethod
    def safe_filename(filename: str, max_length: int = 200) -> str:
        """
        안전한 파일명 생성

        Args:
            filename: 원본 파일명
            max_length: 최대 파일명 길이

        Returns:
            안전한 파일명
        """
        if not filename:
            return "unknown_file"

        # 위험한 문자들을 제거하거나 대체
        safe_chars = re.sub(r'[<>:"/\\|?*]', '_', filename)

        # 연속된 언더스코어를 하나로 정리
        safe_chars = re.sub(r'_+', '_', safe_chars)

        # 앞뒤 공백과 점 제거
        safe_chars = safe_chars.strip('. ')

        # 길이 제한
        if len(safe_chars) > max_length:
            # 확장자 보존
            if '.' in safe_chars:
                name_part, ext_part = safe_chars.rsplit('.', 1)
                max_name_length = max_length - len(ext_part) - 1
                safe_chars = name_part[:max_name_length] + '.' + ext_part
            else:
                safe_chars = safe_chars[:max_length]

        # 빈 파일명 방지
        if not safe_chars or safe_chars in {'.', '..'}:
            safe_chars = "unknown_file"

        return safe_chars

    @staticmethod
    def is_supported_image_file(file_path: Path) -> bool:
        """지원하는 이미지 파일인지 확인"""
        if not file_path.exists():
            return False

        return file_path.suffix.lower() in FileUtils.SUPPORTED_IMAGE_EXTENSIONS

    @staticmethod
    def is_supported_content_type(content_type: str) -> bool:
        """지원하는 Content-Type인지 확인"""
        if not content_type:
            return False

        content_type_lower = content_type.lower()
        return any(supported_type in content_type_lower
                  for supported_type in FileUtils.SUPPORTED_CONTENT_TYPES)

    @staticmethod
    def get_extension_from_content_type(content_type: str) -> str:
        """Content-Type에서 파일 확장자 추출"""
        content_type_to_ext = {
            'image/jpeg': '.jpg',
            'image/jpg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/bmp': '.bmp',
            'image/tiff': '.tiff',
            'image/webp': '.webp'
        }

        content_type_lower = content_type.lower()
        for ct, ext in content_type_to_ext.items():
            if ct in content_type_lower:
                return ext

        return '.tmp'  # 기본 확장자

    @staticmethod
    def extract_filename_from_url(url: str) -> Optional[str]:
        """URL에서 파일명 추출"""
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path

            if path:
                filename = os.path.basename(path)
                if filename and '.' in filename:
                    return filename

            return None

        except Exception as e:
            logging.warning(f"[FileUtils] URL에서 파일명 추출 실패: {e}")
            return None

    @staticmethod
    def generate_temp_filename(url: str, content_type: str = None, prefix: str = "temp") -> str:
        """임시 파일명 생성"""
        try:
            # URL에서 파일명 시도
            filename = FileUtils.extract_filename_from_url(url)
            if filename:
                return FileUtils.safe_filename(filename)

            # URL 해시 기반 파일명 생성
            url_hash = hash(url) % 1000000
            extension = FileUtils.get_extension_from_content_type(content_type) if content_type else '.tmp'

            return f"{prefix}_{url_hash}{extension}"

        except Exception as e:
            logging.warning(f"[FileUtils] 임시 파일명 생성 실패: {e}")
            return f"{prefix}_unknown.tmp"

    @staticmethod
    def get_file_info(file_path: Path) -> Dict[str, Any]:
        """파일 정보 추출"""
        try:
            if not file_path.exists():
                return {"error": "파일이 존재하지 않음"}

            stat = file_path.stat()

            return {
                "name": file_path.name,
                "size": stat.st_size,
                "extension": file_path.suffix.lower(),
                "is_image": FileUtils.is_supported_image_file(file_path),
                "created_time": stat.st_ctime,
                "modified_time": stat.st_mtime,
                "absolute_path": str(file_path.absolute())
            }

        except Exception as e:
            return {"error": f"파일 정보 추출 실패: {str(e)}"}

    @staticmethod
    def cleanup_files(directory: Path, max_age_hours: int = 24, pattern: str = "*") -> int:
        """디렉터리에서 오래된 파일들 정리"""
        try:
            if not directory.exists() or not directory.is_dir():
                return 0

            import time
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            deleted_count = 0

            for file_path in directory.glob(pattern):
                if file_path.is_file():
                    try:
                        file_age = current_time - file_path.stat().st_mtime
                        if file_age > max_age_seconds:
                            file_path.unlink()
                            deleted_count += 1
                            logging.debug(f"[FileUtils] 오래된 파일 삭제: {file_path}")
                    except Exception as e:
                        logging.warning(f"[FileUtils] 파일 삭제 실패 ({file_path}): {e}")

            if deleted_count > 0:
                logging.info(f"[FileUtils] {deleted_count}개 파일 정리 완료")

            return deleted_count

        except Exception as e:
            logging.error(f"[FileUtils] 파일 정리 중 오류: {e}")
            return 0

    @staticmethod
    def ensure_directory(directory: Path) -> bool:
        """디렉터리 생성 확인"""
        try:
            directory.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logging.error(f"[FileUtils] 디렉터리 생성 실패 ({directory}): {e}")
            return False

    @staticmethod
    def get_safe_temp_path(base_dir: Path, filename: str) -> Path:
        """안전한 임시 파일 경로 생성"""
        safe_filename = FileUtils.safe_filename(filename)
        temp_path = base_dir / safe_filename

        # 파일이 이미 존재하면 번호 추가
        counter = 1
        original_path = temp_path

        while temp_path.exists():
            name_part = original_path.stem
            ext_part = original_path.suffix
            temp_path = base_dir / f"{name_part}_{counter}{ext_part}"
            counter += 1

            # 무한 루프 방지
            if counter > 1000:
                import uuid
                unique_id = str(uuid.uuid4())[:8]
                temp_path = base_dir / f"{name_part}_{unique_id}{ext_part}"
                break

        return temp_path

    @staticmethod
    def validate_file_safety(file_path: Path) -> Dict[str, Any]:
        """파일 안전성 검증"""
        try:
            if not file_path.exists():
                return {"safe": False, "reason": "파일이 존재하지 않음"}

            # 파일 크기 체크 (100MB 제한)
            max_size = 100 * 1024 * 1024  # 100MB
            if file_path.stat().st_size > max_size:
                return {"safe": False, "reason": f"파일 크기가 너무 큼 ({file_path.stat().st_size} bytes)"}

            # 이미지 파일 확장자 체크
            if not FileUtils.is_supported_image_file(file_path):
                return {"safe": False, "reason": f"지원하지 않는 파일 형식: {file_path.suffix}"}

            return {"safe": True, "reason": "파일 안전성 검증 완료"}

        except Exception as e:
            return {"safe": False, "reason": f"파일 검증 중 오류: {str(e)}"}