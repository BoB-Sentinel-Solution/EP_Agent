import easyocr
import cv2
import numpy as np
import logging
from pathlib import Path
import base64

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OCREngine:
    """
    효율적인 OCR 처리를 위한 클래스.
    EasyOCR Reader 인스턴스를 한 번만 생성하여 재사용합니다.
    """
    def __init__(self, languages=['ko', 'en']):
        """OCREngine을 초기화하고 EasyOCR Reader를 준비합니다."""
        try:
            self.reader = easyocr.Reader(languages, gpu=True)
            logging.info("EasyOCR Reader가 GPU를 사용하여 초기화되었습니다.")
        except Exception:
            self.reader = easyocr.Reader(languages, gpu=False)
            logging.info("GPU를 사용할 수 없어 EasyOCR Reader가 CPU를 사용하여 초기화되었습니다.")

    def _read_image_safely(self, image_path: str) -> np.ndarray:
        """한글 경로 문제를 해결하기 위해 numpy를 통해 이미지를 읽습니다."""
        try:
            img_array = np.fromfile(image_path, np.uint8)
            image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
            if image is None:
                raise IOError("이미지 파일을 디코딩할 수 없습니다.")
            return image
        except Exception as e:
            logging.error(f"이미지 파일 로드 실패: {image_path}, 오류: {e}")
            return None

    def _process_image_from_bytes(self, image_bytes: bytes) -> np.ndarray:
        """바이트 데이터에서 이미지를 생성합니다."""
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if image is None:
                raise IOError("이미지 바이트를 디코딩할 수 없습니다.")
            return image
        except Exception as e:
            logging.error(f"이미지 바이트 처리 실패: {e}")
            return None

    def _process_image_from_base64(self, base64_data: str) -> np.ndarray:
        """base64 데이터에서 이미지를 생성합니다."""
        try:
            # base64 디코딩
            image_bytes = base64.b64decode(base64_data)
            return self._process_image_from_bytes(image_bytes)
        except Exception as e:
            logging.error(f"base64 이미지 처리 실패: {e}")
            return None

    def extract_text(self, image_path: str, detail: bool = False, preprocess: bool = False) -> list | str | None:
        """이미지 파일에서 텍스트를 추출하는 메인 함수 (기존 기능 유지)"""
        try:
            image = self._read_image_safely(image_path)
            if image is None:
                return None

            if preprocess:
                logging.info("이미지 전처리를 수행합니다...")
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
                image = clahe.apply(gray)

            results = self.reader.readtext(image, detail=1 if detail else 0, paragraph=not detail)

            if detail:
                return [{'text': text, 'confidence': conf, 'bbox': bbox} for bbox, text, conf in results]
            else:
                return '\n'.join(results)

        except Exception as e:
            logging.error(f"OCR 처리 중 오류 발생: {e}")
            return None

    def find_first_keyword(self, image_path: str, keywords: list[str]) -> dict:
        """이미지 파일에서 키워드 검사 (기존 기능 유지)"""
        try:
            image = self._read_image_safely(image_path)
            if image is None:
                return {"found": False, "keyword": None, "context": "이미지 로드 실패"}

            return self._find_keyword_in_image(image, keywords)

        except Exception as e:
            logging.error(f"키워드 탐색 중 오류 발생: {e}")
            return {"found": False, "keyword": None, "context": str(e)}

    def find_first_keyword_from_bytes(self, image_bytes: bytes, keywords: list[str]) -> dict:
        """바이트 데이터에서 키워드 검사 (새 기능)"""
        try:
            image = self._process_image_from_bytes(image_bytes)
            if image is None:
                return {"found": False, "keyword": None, "context": "이미지 처리 실패"}

            return self._find_keyword_in_image(image, keywords)

        except Exception as e:
            logging.error(f"바이트 키워드 탐색 중 오류 발생: {e}")
            return {"found": False, "keyword": None, "context": str(e)}

    def find_first_keyword_from_base64(self, base64_data: str, keywords: list[str]) -> dict:
        """base64 데이터에서 키워드 검사 (새 기능)"""
        try:
            image = self._process_image_from_base64(base64_data)
            if image is None:
                return {"found": False, "keyword": None, "context": "base64 이미지 처리 실패"}

            return self._find_keyword_in_image(image, keywords)

        except Exception as e:
            logging.error(f"base64 키워드 탐색 중 오류 발생: {e}")
            return {"found": False, "keyword": None, "context": str(e)}

    def _find_keyword_in_image(self, image: np.ndarray, keywords: list[str]) -> dict:
        """이미지에서 키워드 검사 (공통 로직)"""
        try:
            # OCR 실행 (상세 모드로 각 텍스트 조각별로 처리)
            results = self.reader.readtext(image, detail=1, paragraph=False)

            # 각 텍스트 조각을 순회하며 키워드 검사
            for (bbox, text, confidence) in results:
                for keyword in keywords:
                    if keyword in text:
                        logging.info(f"키워드 '{keyword}' 발견! OCR 처리를 즉시 중단합니다.")
                        return {
                            "found": True,
                            "keyword": keyword,
                            "context": text,
                            "confidence": confidence
                        }
            
            # 모든 텍스트 조각을 검사했지만 키워드를 찾지 못한 경우
            return {"found": False, "keyword": None, "context": None}

        except Exception as e:
            logging.error(f"이미지 키워드 검사 중 오류: {e}")
            return {"found": False, "keyword": None, "context": str(e)}