#!/usr/bin/env python3
"""
공통 파일 다운로드 모듈

모든 LLM 프로세서에서 공통으로 사용할 수 있는 파일 다운로드 기능을 제공합니다.
- 비동기/동기 다운로드 지원
- 스트리밍 다운로드 (메모리 효율성)
- HTML 응답 검증 (인증 실패 감지)
- 에러 처리 및 재시도 로직
"""

import asyncio
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import requests

# 선택적 의존성
try:
    import httpx
    import aiofiles
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

from .file_utils import FileUtils

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FileDownloader:
    """공통 파일 다운로드 클래스"""

    def __init__(self, temp_dir: Path = None):
        if temp_dir is None:
            self.temp_dir = Path.home() / ".llm_proxy" / "ocr_temp"
        else:
            self.temp_dir = temp_dir

        self.temp_dir.mkdir(parents=True, exist_ok=True)

    async def download_async(self,
                           url: str,
                           headers: Dict[str, str] = None,
                           cert_path: Path = None,
                           filename: str = None) -> Optional[Path]:
        """비동기 파일 다운로드"""
        if not ASYNC_AVAILABLE:
            # 비동기 라이브러리가 없으면 동기 다운로드로 폴백
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self.download_sync, url, headers, cert_path, filename
            )

        try:
            logging.info(f"[DOWNLOAD] 비동기 다운로드 시작: {url}")

            verify = str(cert_path) if cert_path else True

            async with httpx.AsyncClient(verify=verify, follow_redirects=True) as client:
                async with client.stream(
                    "GET", url,
                    headers=headers or {},
                    timeout=60.0
                ) as response:

                    # HTML 응답 검증 (인증 실패 가능성)
                    content_type = response.headers.get("content-type", "").lower()
                    if "text/html" in content_type:
                        logging.warning("[DOWNLOAD] HTML 응답 수신. 인증 실패 가능성이 높습니다.")
                        return None

                    response.raise_for_status()

                    # 파일 경로 생성
                    file_path = self._generate_file_path(url, content_type, filename)

                    # 스트리밍 다운로드
                    async with aiofiles.open(file_path, 'wb') as f:
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            if chunk:
                                await f.write(chunk)

                    logging.info(f"[DOWNLOAD] 비동기 다운로드 완료: {file_path}")
                    return file_path

        except httpx.TimeoutException:
            logging.error("[DOWNLOAD] 비동기 다운로드 타임아웃")
            return None
        except httpx.RequestError as e:
            logging.error(f"[DOWNLOAD] 비동기 다운로드 요청 오류: {e}")
            return None
        except Exception as e:
            logging.error(f"[DOWNLOAD] 비동기 다운로드 실패: {e}")
            return None

    def download_sync(self,
                     url: str,
                     headers: Dict[str, str] = None,
                     cert_path: Path = None,
                     filename: str = None) -> Optional[Path]:
        """동기 파일 다운로드 (폴백용)"""
        try:
            logging.info(f"[DOWNLOAD] 동기 다운로드 시작: {url}")

            verify = str(cert_path) if cert_path else True

            with requests.get(
                url,
                headers=headers or {},
                stream=True,
                verify=verify,
                timeout=60,
                allow_redirects=True
            ) as response:

                # HTML 응답 검증 (인증 실패 가능성)
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    logging.warning("[DOWNLOAD] HTML 응답 수신. 인증 실패 가능성이 높습니다.")
                    return None

                response.raise_for_status()

                # 파일 경로 생성
                file_path = self._generate_file_path(url, content_type, filename)

                # 스트리밍 다운로드
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                logging.info(f"[DOWNLOAD] 동기 다운로드 완료: {file_path}")
                return file_path

        except requests.exceptions.Timeout:
            logging.error("[DOWNLOAD] 동기 다운로드 타임아웃")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"[DOWNLOAD] 동기 다운로드 요청 오류: {e}")
            return None
        except Exception as e:
            logging.error(f"[DOWNLOAD] 동기 다운로드 실패: {e}")
            return None

    async def download(self,
                      url: str,
                      headers: Dict[str, str] = None,
                      cert_path: Path = None,
                      filename: str = None,
                      prefer_async: bool = True) -> Optional[Path]:
        """파일 다운로드 (비동기 우선, 동기 폴백)"""
        if prefer_async and ASYNC_AVAILABLE:
            return await self.download_async(url, headers, cert_path, filename)
        else:
            if asyncio.iscoroutinefunction(self.download_sync):
                return await self.download_sync(url, headers, cert_path, filename)
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self.download_sync, url, headers, cert_path, filename
                )

    def _generate_file_path(self, url: str, content_type: str, filename: str = None) -> Path:
        """파일 경로 생성"""
        if filename:
            safe_name = FileUtils.safe_filename(filename)
        else:
            # URL에서 파일명 추출하거나 임시 파일명 생성
            import os
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path_name = os.path.basename(parsed.path)

            if path_name and '.' in path_name:
                safe_name = FileUtils.safe_filename(path_name)
            else:
                # Content-Type에서 확장자 추출
                extension = self._get_extension_from_content_type(content_type)
                safe_name = f"download_{hash(url) % 1000000}{extension}"

        return self.temp_dir / safe_name

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

    def is_supported_content_type(self, content_type: str) -> bool:
        """지원하는 파일 형식인지 확인"""
        supported_types = [
            "image/jpeg", "image/jpg", "image/png", "image/gif",
            "image/bmp", "image/tiff", "image/webp"
        ]
        return any(supported_type in content_type.lower() for supported_type in supported_types)

    def cleanup_temp_files(self, max_age_hours: int = 24):
        """오래된 임시 파일들을 정리"""
        try:
            import time
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600

            for temp_file in self.temp_dir.glob("*"):
                if temp_file.is_file():
                    file_age = current_time - temp_file.stat().st_mtime
                    if file_age > max_age_seconds:
                        temp_file.unlink()
                        logging.debug(f"[DOWNLOAD] 오래된 임시 파일 삭제: {temp_file}")

        except Exception as e:
            logging.warning(f"[DOWNLOAD] 임시 파일 정리 중 오류: {e}")