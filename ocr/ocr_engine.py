#!/usr/bin/env python3
"""
독립적 OCR 엔진 - 재사용 가능한 유틸리티
LLM, MCP, API 등 모든 환경에서 사용 가능
"""

from pathlib import Path
from typing import Optional, Dict, Any
import time
import logging

# OCR 라이브러리들 (선택적 임포트)
try:
    import pytesseract
    from PIL import Image
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    import easyocr
    EASYOCR_AVAILABLE = True
except ImportError:
    EASYOCR_AVAILABLE = False

try:
    import cv2
    import numpy as np
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False


class OCREngine:
    """재사용 가능한 순수 OCR 처리 엔진"""
    
    def __init__(self, preferred_engine: str = "auto"):
        """
        Args:
            preferred_engine: "tesseract", "easyocr", "auto"
        """
        self.preferred_engine = preferred_engine
        self.available_engines = self._check_available_engines()
        self.easyocr_reader = None
        
        if not self.available_engines:
            raise RuntimeError("OCR 엔진이 설치되지 않았습니다. pytesseract 또는 easyocr을 설치해주세요.")
        
        self.logger = logging.getLogger(__name__)
    
    def _check_available_engines(self) -> Dict[str, bool]:
        """사용 가능한 OCR 엔진 확인"""
        return {
            "tesseract": TESSERACT_AVAILABLE,
            "easyocr": EASYOCR_AVAILABLE,
            "opencv": OPENCV_AVAILABLE
        }
    
    def _get_engine_to_use(self) -> str:
        """사용할 OCR 엔진 결정"""
        if self.preferred_engine == "auto":
            if self.available_engines["easyocr"]:
                return "easyocr"
            elif self.available_engines["tesseract"]:
                return "tesseract"
        else:
            if self.available_engines.get(self.preferred_engine, False):
                return self.preferred_engine
        
        # 폴백: 사용 가능한 첫 번째 엔진
        for engine, available in self.available_engines.items():
            if available:
                return engine
        
        raise RuntimeError("사용 가능한 OCR 엔진이 없습니다.")
    
    def is_supported_image(self, file_path: Path) -> bool:
        """지원하는 이미지 파일인지 확인"""
        supported_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.tiff'}
        return file_path.suffix.lower() in supported_extensions
    
    def preprocess_image(self, image_path: Path) -> Optional[Path]:
        """이미지 전처리 (OCR 정확도 향상)"""
        if not OPENCV_AVAILABLE:
            return image_path
        
        try:
            # 이미지 로드
            img = cv2.imread(str(image_path))
            if img is None:
                return image_path
            
            # 그레이스케일 변환
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # 노이즈 제거
            denoised = cv2.medianBlur(gray, 3)
            
            # 대비 향상
            enhanced = cv2.convertScaleAbs(denoised, alpha=1.2, beta=10)
            
            # 전처리된 파일 저장
            preprocessed_path = image_path.parent / f"preprocessed_{image_path.name}"
            cv2.imwrite(str(preprocessed_path), enhanced)
            
            return preprocessed_path
        except Exception as e:
            self.logger.warning(f"이미지 전처리 실패: {e}")
            return image_path
    
    def extract_text_with_tesseract(self, image_path: Path) -> str:
        """Tesseract를 사용한 텍스트 추출"""
        try:
            # 한국어 + 영어 설정
            custom_config = r'--oem 3 --psm 6 -l kor+eng'
            
            with Image.open(image_path) as image:
                text = pytesseract.image_to_string(image, config=custom_config)
            
            return text.strip()
        except Exception as e:
            self.logger.error(f"Tesseract OCR 실패: {e}")
            return ""
    
    def extract_text_with_easyocr(self, image_path: Path) -> str:
        """EasyOCR을 사용한 텍스트 추출"""
        try:
            # EasyOCR 리더 초기화 (한 번만)
            if self.easyocr_reader is None:
                self.easyocr_reader = easyocr.Reader(['ko', 'en'])
            
            results = self.easyocr_reader.readtext(str(image_path))
            
            # 결과 텍스트 합치기
            texts = []
            for (bbox, text, confidence) in results:
                if confidence > 0.5:  # 신뢰도 50% 이상만
                    texts.append(text)
            
            return '\n'.join(texts)
        except Exception as e:
            self.logger.error(f"EasyOCR 실패: {e}")
            return ""
    
    def extract_text(self, file_path: Path) -> Dict[str, Any]:
        """
        메인 텍스트 추출 함수
        
        Returns:
            {
                "success": bool,
                "text": str,
                "engine": str,
                "processing_time": float,
                "confidence": float
            }
        """
        start_time = time.time()
        
        if not self.is_supported_image(file_path):
            return {
                "success": False,
                "text": "",
                "engine": "none",
                "processing_time": 0.0,
                "confidence": 0.0,
                "error": "지원하지 않는 파일 형식"
            }
        
        if not file_path.exists():
            return {
                "success": False,
                "text": "",
                "engine": "none", 
                "processing_time": 0.0,
                "confidence": 0.0,
                "error": "파일을 찾을 수 없음"
            }
        
        # 사용할 엔진 결정
        engine = self._get_engine_to_use()
        
        # 이미지 전처리
        processed_image = self.preprocess_image(file_path)
        
        # OCR 실행
        text = ""
        try:
            if engine == "easyocr":
                text = self.extract_text_with_easyocr(processed_image)
            elif engine == "tesseract":
                text = self.extract_text_with_tesseract(processed_image)
            
            success = len(text.strip()) > 0
            confidence = 0.8 if success else 0.0
            
        except Exception as e:
            self.logger.error(f"OCR 처리 실패: {e}")
            success = False
            confidence = 0.0
        
        finally:
            # 전처리된 임시 파일 정리
            if processed_image != file_path and processed_image.exists():
                try:
                    processed_image.unlink()
                except Exception:
                    pass
        
        processing_time = time.time() - start_time
        
        return {
            "success": success,
            "text": text.strip(),
            "engine": engine,
            "processing_time": processing_time,
            "confidence": confidence
        }


# 편의 함수
def extract_text_from_image(image_path: Path, engine: str = "auto") -> str:
    """간단한 텍스트 추출 함수"""
    ocr = OCREngine(preferred_engine=engine)
    result = ocr.extract_text(image_path)
    return result.get("text", "")