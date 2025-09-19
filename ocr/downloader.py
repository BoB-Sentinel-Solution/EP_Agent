# downloader.py
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
import re
from llm_parser.common.utils import FileUtils
from ocr.ocr_engine import OCREngine
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



async def process_ocr_if_image(file_path: Path) -> Optional[Dict[str, Any]]:
    """이미지 파일인 경우 OCR 처리 수행"""
    try:
        # OCR 엔진 초기화
        ocr_engine = OCREngine(preferred_engine="auto")
        
        # 이미지 파일인지 확인
        if not ocr_engine.is_supported_image(file_path):
            print(f"[INFO] OCR 지원하지 않는 파일 형식: {file_path.suffix}")
            return None
        
        print(f"[INFO] OCR 처리 시작: {file_path.name}")
        
        # 비동기 환경에서 OCR 처리 (별도 스레드에서 실행)
        loop = asyncio.get_event_loop()
        ocr_result = await loop.run_in_executor(None, ocr_engine.extract_text, file_path)
        
        if ocr_result["success"]:
            print(f"[SUCCESS] OCR 처리 완료 - 엔진: {ocr_result['engine']}, "
                  f"처리시간: {ocr_result['processing_time']:.2f}초, "
                  f"추출된 텍스트 길이: {len(ocr_result['text'])}자")
            
            # OCR 결과를 텍스트 파일로 저장
            text_file_path = file_path.parent / f"{file_path.stem}_ocr.txt"
            async with aiofiles.open(text_file_path, 'w', encoding='utf-8') as f:
                await f.write(f"=== OCR 결과 ===\n")
                await f.write(f"원본 파일: {file_path.name}\n")
                await f.write(f"OCR 엔진: {ocr_result['engine']}\n")
                await f.write(f"처리 시간: {ocr_result['processing_time']:.2f}초\n")
                await f.write(f"신뢰도: {ocr_result['confidence']:.2f}\n")
                await f.write(f"생성 시간: {asyncio.get_event_loop().time()}\n")
                await f.write(f"\n=== 추출된 텍스트 ===\n")
                await f.write(ocr_result['text'])
            
            print(f"[INFO] OCR 결과 저장 완료: {text_file_path}")
            
            return {
                **ocr_result,
                "text_file_path": text_file_path
            }
        else:
            print(f"[FAILURE] OCR 처리 실패: {ocr_result.get('error', '알 수 없는 오류')}")
            return ocr_result
            
    except Exception as e:
        import traceback
        print(f"[ERROR] OCR 처리 중 예외 발생: {e}\n{traceback.format_exc()}")
        return None


async def download_file(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[Dict[str, Any]]:
    """
    파일을 다운로드하고 이미지인 경우 OCR 처리까지 수행
    
    Returns:
        {
            "file_path": Path,
            "ocr_result": Optional[Dict[str, Any]]
        }
    """
    # 파일 다운로드
    if httpx and aiofiles:
        file_path = await _async_download(file_info, download_dir, cert_path)
    else:
        loop = asyncio.get_event_loop()
        file_path = await loop.run_in_executor(None, _sync_download, file_info, download_dir, cert_path)
    
    if not file_path:
        return None
    
    result = {
        "file_path": file_path,
        "ocr_result": None
    }
    
    # 이미지 파일인 경우 OCR 처리
    ocr_result = await process_ocr_if_image(file_path)
    if ocr_result:
        result["ocr_result"] = ocr_result
    
    return result


# 편의 함수들
async def download_and_ocr(file_info: Dict[str, Any], download_dir: Path, cert_path: Path) -> Optional[str]:
    """다운로드 후 OCR 텍스트만 반환하는 간단한 함수"""
    result = await download_file(file_info, download_dir, cert_path)
    if result and result.get("ocr_result"):
        return result["ocr_result"]["text"]
    return None


def get_ocr_summary(ocr_result: Optional[Dict[str, Any]]) -> str:
    """OCR 결과 요약 문자열 생성"""
    if not ocr_result:
        return "OCR 처리되지 않음"
    
    if not ocr_result["success"]:
        return f"OCR 실패: {ocr_result.get('error', '알 수 없는 오류')}"
    
    text_preview = ocr_result["text"][:100] + "..." if len(ocr_result["text"]) > 100 else ocr_result["text"]
    return (f"OCR 성공 (엔진: {ocr_result['engine']}, "
            f"처리시간: {ocr_result['processing_time']:.2f}초, "
            f"텍스트: {text_preview})")