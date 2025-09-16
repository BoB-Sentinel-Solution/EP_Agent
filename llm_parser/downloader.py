# downloader.py
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
import re
from pathlib import Path
from datetime import datetime

# 선택적 의존성
try:
    import httpx
    import aiofiles
except ImportError:
    httpx = None
    aiofiles = None

class FileUtils:
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        # ... (기존 코드와 동일) ...
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types

    @staticmethod
    def safe_filename(original_name: str) -> str:
        # ... (기존 코드와 동일) ...
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:30]
        return f"{timestamp}_{safe_stem}{ext}"

async def _async_download(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """httpx + aiofiles 기반 비동기 다운로드"""
    # ... (기존 _async_download_with_httpx 코드) ...
    # self.download_dir 대신 인자로 받은 download_dir 사용
    safe_name = FileUtils.safe_filename(file_info["file_name"])
    file_path = download_dir / safe_name
    # ...
    return file_path

def _sync_download(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """동기 다운로드 폴백 (requests 사용)"""
    # ... (기존 _sync_download_with_requests 코드) ...
    # self.download_dir 대신 인자로 받은 download_dir 사용
    safe_name = FileUtils.safe_filename(file_info["file_name"])
    file_path = download_dir / safe_name
    # ...
    return file_path

async def download_file(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """적절한 방법으로 파일을 다운로드 (비동기 우선, 없으면 동기 폴백)"""
    if httpx:
        return await _async_download(file_info, download_dir, cert_path)
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_download, file_info, download_dir, cert_path)