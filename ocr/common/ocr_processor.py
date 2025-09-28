#!/usr/bin/env python3
"""
공통 OCR 처리 모듈

모든 LLM 프로세서에서 공통으로 사용할 수 있는 OCR 및 보안 키워드 검사 기능을 제공합니다.
- 이미지 파일 OCR 처리
- 보안 키워드 검사
- OCR 결과 저장
- 비동기 처리 지원
"""

import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

# 선택적 의존성
try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

from ..ocr_engine import OCREngine
from security.keyword_manager import KeywordManager

# 로깅 설정 (UTF-8 강제)
import sys
import os
if sys.platform == "win32":
    os.system("chcp 65001 > nul")
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

class OCRProcessor:
    """공통 OCR 처리 클래스"""

    def __init__(self, languages: List[str] = None):
        if languages is None:
            languages = ['ko', 'en']

        try:
            self.ocr_engine = OCREngine(languages)
            self.keyword_manager = KeywordManager()
            logging.info("OCR 프로세서 초기화 완료")
        except Exception as e:
            logging.error(f"OCR 프로세서 초기화 실패: {e}")
            self.ocr_engine = None
            self.keyword_manager = None

    def is_initialized(self) -> bool:
        """OCR 엔진과 키워드 매니저가 정상 초기화되었는지 확인"""
        return self.ocr_engine is not None and self.keyword_manager is not None

    def is_image_file(self, file_path: Path) -> bool:
        """이미지 파일인지 확인"""
        if not file_path.exists():
            return False

        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
        return file_path.suffix.lower() in image_extensions

    def process_image_with_keywords(self, file_path: Path, keywords: List[str] = None) -> Dict[str, Any]:
        """
        이미지 파일을 OCR 처리하고 키워드 검사

        Args:
            file_path: 이미지 파일 경로
            keywords: 검사할 키워드 목록 (None이면 DB에서 가져옴)

        Returns:
            {
                "success": bool,
                "blocked": bool,
                "keyword": str,  # 발견된 키워드 (blocked=True일 때)
                "context": str,  # 키워드 문맥 (blocked=True일 때)
                "confidence": float,  # OCR 신뢰도
                "text": str,  # 추출된 전체 텍스트
                "reason": str  # 처리 결과 이유
            }
        """
        if not self.is_initialized():
            return {
                "success": False,
                "blocked": False,
                "reason": "OCR 엔진 또는 키워드 관리자 미초기화"
            }

        if not self.is_image_file(file_path):
            return {
                "success": False,
                "blocked": False,
                "reason": f"이미지 파일이 아님: {file_path.suffix}"
            }

        try:
            # 키워드 목록 가져오기
            if keywords is None:
                keywords = self.keyword_manager.get_keywords()

            if not keywords:
                logging.warning("[OCR] 검사할 키워드가 없습니다.")
                return {
                    "success": False,
                    "blocked": False,
                    "reason": "검사할 키워드가 없음"
                }

            logging.info(f"[OCR] 이미지 OCR 처리 시작: {file_path.name} (키워드 수: {len(keywords)})")

            # OCR 처리 및 키워드 검사 (한번에 처리)
            result = self.ocr_engine.find_first_keyword(str(file_path), keywords)

            if result["found"]:
                logging.warning(
                    f"[OCR] ⚠️ 보안 키워드 발견! "
                    f"키워드: '{result['keyword']}', 문맥: '{result['context'][:50]}...'"
                )
                return {
                    "success": True,
                    "blocked": True,
                    "keyword": result["keyword"],
                    "context": result["context"],
                    "confidence": result.get("confidence", 0),
                    "text": result["context"],  # 키워드가 포함된 텍스트
                    "reason": f"보안 키워드 '{result['keyword']}' 탐지됨"
                }
            else:
                logging.info("[OCR] ✅ 보안 키워드 없음")

                # 전체 텍스트 추출 (필요시)
                full_text = self.ocr_engine.extract_text(str(file_path))
                text_content = full_text if isinstance(full_text, str) else ""

                return {
                    "success": True,
                    "blocked": False,
                    "keyword": None,
                    "context": None,
                    "confidence": 0,
                    "text": text_content,
                    "reason": "보안 키워드 없음"
                }

        except Exception as e:
            logging.error(f"[OCR] 이미지 처리 중 오류: {e}")
            return {
                "success": False,
                "blocked": False,
                "reason": f"OCR 처리 오류: {str(e)}"
            }

    async def process_image_with_keywords_async(self, file_path: Path, keywords: List[str] = None) -> Dict[str, Any]:
        """비동기 이미지 OCR 처리 및 키워드 검사"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.process_image_with_keywords, file_path, keywords)

    def extract_text_only(self, file_path: Path) -> Dict[str, Any]:
        """이미지에서 텍스트만 추출 (키워드 검사 없이)"""
        if not self.is_initialized():
            return {
                "success": False,
                "text": "",
                "reason": "OCR 엔진 미초기화"
            }

        if not self.is_image_file(file_path):
            return {
                "success": False,
                "text": "",
                "reason": f"이미지 파일이 아님: {file_path.suffix}"
            }

        try:
            logging.info(f"[OCR] 텍스트 추출 시작: {file_path.name}")

            text = self.ocr_engine.extract_text(str(file_path))
            text_content = text if isinstance(text, str) else ""

            logging.info(f"[OCR] 텍스트 추출 완료: {len(text_content)}자")

            return {
                "success": True,
                "text": text_content,
                "reason": "텍스트 추출 완료"
            }

        except Exception as e:
            logging.error(f"[OCR] 텍스트 추출 중 오류: {e}")
            return {
                "success": False,
                "text": "",
                "reason": f"텍스트 추출 오류: {str(e)}"
            }

    async def save_ocr_result_async(self, file_path: Path, ocr_result: Dict[str, Any]) -> Optional[Path]:
        """OCR 결과를 텍스트 파일로 저장 (비동기)"""
        if not AIOFILES_AVAILABLE or not ocr_result.get("success", False):
            return None

        try:
            result_file_path = file_path.parent / f"{file_path.stem}_ocr_result.txt"

            if AIOFILES_AVAILABLE:
                async with aiofiles.open(result_file_path, 'w', encoding='utf-8') as f:
                    await f.write("=== OCR 처리 결과 ===\n")
                    await f.write(f"원본 파일: {file_path.name}\n")
                    await f.write(f"처리 시간: {asyncio.get_event_loop().time()}\n")
                    await f.write(f"성공 여부: {ocr_result.get('success', False)}\n")
                    await f.write(f"차단 여부: {ocr_result.get('blocked', False)}\n")

                    if ocr_result.get("blocked"):
                        await f.write(f"발견된 키워드: {ocr_result.get('keyword', 'N/A')}\n")
                        await f.write(f"키워드 문맥: {ocr_result.get('context', 'N/A')}\n")

                    await f.write(f"OCR 신뢰도: {ocr_result.get('confidence', 0):.2f}\n")
                    await f.write(f"\n=== 추출된 텍스트 ===\n")
                    await f.write(ocr_result.get('text', ''))
            else:
                with open(result_file_path, 'w', encoding='utf-8') as f:
                    f.write("=== OCR 처리 결과 ===\n")
                    f.write(f"원본 파일: {file_path.name}\n")
                    f.write(f"처리 시간: {asyncio.get_event_loop().time()}\n")
                    f.write(f"성공 여부: {ocr_result.get('success', False)}\n")
                    f.write(f"차단 여부: {ocr_result.get('blocked', False)}\n")

                    if ocr_result.get("blocked"):
                        f.write(f"발견된 키워드: {ocr_result.get('keyword', 'N/A')}\n")
                        f.write(f"키워드 문맥: {ocr_result.get('context', 'N/A')}\n")

                    f.write(f"OCR 신뢰도: {ocr_result.get('confidence', 0):.2f}\n")
                    f.write(f"\n=== 추출된 텍스트 ===\n")
                    f.write(ocr_result.get('text', ''))

            logging.info(f"[OCR] 결과 저장 완료: {result_file_path}")
            return result_file_path

        except Exception as e:
            logging.error(f"[OCR] 결과 저장 실패: {e}")
            return None

    def get_keyword_stats(self) -> Dict[str, Any]:
        """키워드 통계 정보 반환"""
        if not self.keyword_manager:
            return {"error": "키워드 매니저 미초기화"}

        keywords = self.keyword_manager.get_keywords()
        return {
            "total_keywords": len(keywords),
            "keywords": keywords
        }