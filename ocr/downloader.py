# downloader.py
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
import re
from llm_parser.common.utils import FileUtils

# 선택적 의존성
try:
    import httpx
    import aiofiles
except ImportError:
    httpx = None
    aiofiles = None


async def _async_download(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """httpx + aiofiles 기반 비동기 다운로드"""
    try:
        download_url = file_info["download_url"]
        file_name = file_info["file_name"]
        # 1. 어댑터가 전달해 준 헤더를 꺼냅니다.
        headers = file_info.get("headers", {})
        
        async with httpx.AsyncClient(verify=str(cert_path), follow_redirects=True) as client:
            # 2. http 요청에 수집된 headers를 그대로 전달합니다.
            async with client.stream("GET", download_url, headers=headers, timeout=60.0) as response:
                # 응답이 HTML이면 인증 실패로 간주하고 차단
                if "text/html" in response.headers.get("content-type", "").lower():
                    print("[FAILURE] HTML 응답 수신. 인증 실패 가능성이 높습니다.")
                    return None
                
                response.raise_for_status()
                
                safe_name = FileUtils.safe_filename(file_name)
                file_path = download_dir / safe_name
                async with aiofiles.open(file_path, 'wb') as f:
                    async for chunk in response.aiter_bytes():
                        await f.write(chunk)
                return file_path
    except Exception as e:
        print(f"[ERROR] 비동기 다운로드 실패: {e}")
        return None


def _sync_download(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """동기 다운로드 폴백 (requests 사용)"""
    try:
        download_url = file_info["download_url"]
        file_name = file_info["file_name"]
        # 1. 어댑터가 전달해 준 헤더를 꺼냅니다.
        headers = file_info.get("headers", {})
        
        # 2. http 요청에 수집된 headers를 그대로 전달합니다.
        with requests.get(download_url, headers=headers, stream=True, verify=str(cert_path), timeout=60, allow_redirects=True) as r:
            if "text/html" in r.headers.get("content-type", "").lower():
                print("[FAILURE] HTML 응답 수신. 인증 실패 가능성이 높습니다.")
                return None
            
            r.raise_for_status()

            safe_name = FileUtils.safe_filename(file_name)
            file_path = download_dir / safe_name
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return file_path
    except Exception as e:
        print(f"[ERROR] 동기 다운로드 실패: {e}")
        return None

async def download_file(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Path]:
    """적절한 방법으로 파일을 다운로드 (비동기 우선, 없으면 동기 폴백)"""
    if httpx:
        return await _async_download(file_info, download_dir, cert_path)
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_download, file_info, download_dir, cert_path)


