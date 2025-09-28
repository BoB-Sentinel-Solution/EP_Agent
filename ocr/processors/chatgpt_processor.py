#!/usr/bin/env python3
"""
ChatGPT 파일 처리 프로세서

files.oaiusercontent.com을 통한 ChatGPT 파일 업로드를 감지하고
OCR 처리하여 보안 키워드를 검사합니다.

공통 모듈을 사용하여 다운로드와 OCR 처리를 수행합니다.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List
from mitmproxy import http
from pathlib import Path

from .base_processor import BaseLLMProcessor
from ..common import FileDownloader, OCRProcessor, FileUtils

# 로깅 설정 (UTF-8 강제)
import sys
import os
if sys.platform == "win32":
    os.system("chcp 65001 > nul")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

# UTF-8 출력 강제
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

class ChatGPTProcessor(BaseLLMProcessor):
    """ChatGPT 파일 처리 프로세서"""

    @property
    def name(self) -> str:
        return "ChatGPT"

    def setup_processor(self):
        """ChatGPT 프로세서 초기화 (공통 모듈 사용)"""
        try:
            # 공통 모듈 초기화
            self.file_downloader = FileDownloader(self.temp_dir)
            self.ocr_processor = OCRProcessor(['ko', 'en'])
            logging.info("ChatGPT 파일 프로세서 초기화 완료 (공통 모듈 사용)")
        except Exception as e:
            logging.error(f"ChatGPT 파일 프로세서 초기화 실패: {e}")
            self.file_downloader = None
            self.ocr_processor = None

    def get_supported_hosts(self) -> List[str]:
        """ChatGPT에서 사용하는 파일 호스트 목록"""
        return [
            "files.oaiusercontent.com",
            "cdn.oaiusercontent.com"  # 추가 가능한 호스트
        ]

    def is_file_upload_request(self, flow: http.HTTPFlow) -> bool:
        """ChatGPT 파일 업로드 요청인지 확인 (사전 차단용)"""
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path

        # 🎯 핵심: files.oaiusercontent.com으로의 실제 파일 업로드 요청
        # PUT 방식이 주로 사용되므로 PUT을 우선 탐지
        if self.can_handle(host) and method == "PUT":
            logging.info(f"[ChatGPT] PUT 파일 업로드 요청 감지: {method} {host}{path}")
            return True

        # POST 방식도 지원 (multipart/form-data 업로드)
        if self.can_handle(host) and method == "POST":
            content_type = flow.request.headers.get("content-type", "").lower()
            if "multipart/form-data" in content_type or "image/" in content_type:
                logging.info(f"[ChatGPT] POST 파일 업로드 요청 감지: {method} {host}{path}")
                return True

        return False

    # extract_file_url은 사전 차단 방식에서 불필요함 (제거됨)

    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[bytes]:
        """
        files.oaiusercontent.com 업로드 요청에서 파일 데이터 직접 추출

        Returns:
            파일 바이너리 데이터 또는 None
        """
        try:
            method = flow.request.method
            content_type = flow.request.headers.get("content-type", "").lower()
            content = flow.request.content

            if not content:
                logging.warning(f"[ChatGPT] {method} 업로드 요청에 파일 데이터가 없음")
                return None

            logging.info(f"[ChatGPT] 파일 데이터 추출 시작: {method} {content_type} ({len(content)} bytes)")

            # 1. PUT 방식: 직접 바이너리 업로드 (files.oaiusercontent.com 주요 방식)
            if method == "PUT":
                # PUT은 보통 raw binary 데이터로 전송됨
                if len(content) > 100:  # 최소 파일 크기 체크
                    logging.info(f"[ChatGPT] PUT 바이너리 파일 업로드 감지: {len(content)} bytes")
                    return content
                else:
                    logging.warning(f"[ChatGPT] PUT 요청이지만 파일 크기가 너무 작음: {len(content)} bytes")
                    return None

            # 2. POST 방식: multipart/form-data 처리
            elif method == "POST" and "multipart/form-data" in content_type:
                return self._extract_file_from_multipart(content, content_type)

            # 3. POST 방식: 직접 바이너리 업로드
            elif method == "POST" and any(img_type in content_type for img_type in ["image/", "application/octet-stream"]):
                logging.info(f"[ChatGPT] POST 직접 바이너리 파일 업로드 감지: {content_type}")
                return content

            # 4. 기타 형식
            else:
                logging.warning(f"[ChatGPT] 알 수 없는 업로드 형식: {method} {content_type}")
                return None

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 데이터 추출 중 오류: {e}")
            return None

    def _extract_file_from_multipart(self, content: bytes, content_type: str) -> Optional[bytes]:
        """multipart/form-data에서 파일 추출"""
        try:
            import re

            # boundary 추출
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            if not boundary_match:
                logging.warning("[ChatGPT] multipart boundary를 찾을 수 없음")
                return None

            boundary = boundary_match.group(1).strip('"')
            boundary_bytes = f"--{boundary}".encode()

            # multipart 데이터 분할
            parts = content.split(boundary_bytes)

            for part in parts:
                if not part.strip():
                    continue

                # 헤더와 데이터 분리
                if b'\r\n\r\n' in part:
                    headers_section, data_section = part.split(b'\r\n\r\n', 1)
                    headers_text = headers_section.decode('utf-8', errors='ignore')

                    # 파일 데이터인지 확인 (Content-Type: image/* 또는 filename 존재)
                    if ('content-type:' in headers_text.lower() and
                        any(img_type in headers_text.lower() for img_type in ['image/', 'application/octet-stream'])):

                        # multipart 끝 마커 제거
                        file_data = data_section.rstrip(b'\r\n--')

                        if len(file_data) > 100:  # 최소 파일 크기 체크
                            logging.info(f"[ChatGPT] multipart에서 파일 데이터 추출 성공: {len(file_data)} bytes")
                            return file_data

            logging.warning("[ChatGPT] multipart에서 파일 데이터를 찾을 수 없음")
            return None

        except Exception as e:
            logging.error(f"[ChatGPT] multipart 파일 추출 중 오류: {e}")
            return None


    def process_upload_request_precheck(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        """
        업로드 요청을 사전 차단하기 위한 OCR 검사 (🎯 핵심 메서드)

        Args:
            flow: mitmproxy HTTP 플로우 (업로드 요청)

        Returns:
            {
                "blocked": bool,
                "keyword": str,  # 발견된 키워드 (blocked=True일 때)
                "context": str,  # 키워드 문맥 (blocked=True일 때)
                "reason": str,   # 처리 결과 이유
                "confidence": float  # OCR 신뢰도 (선택적)
            }
        """
        if not self.ocr_processor:
            return {
                "blocked": False,
                "reason": "OCR 프로세서 미초기화"
            }

        if not self.ocr_processor.is_initialized():
            return {
                "blocked": False,
                "reason": "OCR 엔진 또는 키워드 관리자 미초기화"
            }

        try:
            logging.info("[ChatGPT-PRECHECK] 업로드 요청 사전 검사 시작")

            # 1. 요청에서 파일 데이터 추출
            file_data = self.extract_file_from_upload_request(flow)
            if not file_data:
                logging.warning("[ChatGPT-PRECHECK] 파일 데이터 추출 실패")
                return {"blocked": False, "reason": "파일 데이터 추출 실패"}

            # 2. 임시 파일 생성 (Content-Type에 따른 적절한 확장자)
            import tempfile
            content_type = flow.request.headers.get("content-type", "").lower()
            method = flow.request.method

            # Content-Type에서 적절한 확장자 추출
            if "image/png" in content_type:
                suffix = ".png"
            elif "image/jpeg" in content_type or "image/jpg" in content_type:
                suffix = ".jpg"
            elif "image/gif" in content_type:
                suffix = ".gif"
            elif "image/bmp" in content_type:
                suffix = ".bmp"
            elif "image/webp" in content_type:
                suffix = ".webp"
            else:
                suffix = ".png"  # 기본값

            temp_file = tempfile.NamedTemporaryFile(
                delete=False,
                dir=self.temp_dir,
                suffix=suffix
            )
            temp_file.write(file_data)
            temp_file.close()
            temp_path = Path(temp_file.name)

            logging.info(f"[ChatGPT-PRECHECK] 임시 파일 생성: {temp_path} ({len(file_data)} bytes)")

            try:
                # 3. 파일 안전성 검증
                safety_check = FileUtils.validate_file_safety(temp_path)
                if not safety_check["safe"]:
                    logging.warning(f"[ChatGPT-PRECHECK] 파일 안전성 검증 실패: {safety_check['reason']}")
                    return {"blocked": False, "reason": f"파일 안전성 검증 실패: {safety_check['reason']}"}

                # 4. OCR 처리 및 키워드 검사
                logging.info("[ChatGPT-PRECHECK] OCR 처리 및 키워드 검사 시작")

                ocr_result = self.ocr_processor.process_image_with_keywords(temp_path)

                if not ocr_result["success"]:
                    logging.warning(f"[ChatGPT-PRECHECK] OCR 처리 실패: {ocr_result['reason']}")
                    return {"blocked": False, "reason": f"OCR 처리 실패: {ocr_result['reason']}"}

                if ocr_result["blocked"]:
                    logging.warning(
                        f"[ChatGPT-PRECHECK] 🚨 보안 키워드 발견! "
                        f"키워드: '{ocr_result['keyword']}', 문맥: '{ocr_result['context'][:50]}...'"
                    )

                    return {
                        "blocked": True,
                        "keyword": ocr_result["keyword"],
                        "context": ocr_result["context"],
                        "confidence": ocr_result.get("confidence", 0),
                        "reason": f"보안 키워드 '{ocr_result['keyword']}' 탐지됨"
                    }
                else:
                    logging.info("[ChatGPT-PRECHECK] ✅ 보안 키워드 없음, 업로드 허용")
                    return {"blocked": False, "reason": "보안 키워드 없음"}

            finally:
                # 5. 임시 파일 정리
                try:
                    temp_path.unlink()
                    logging.debug(f"[ChatGPT-PRECHECK] 임시 파일 삭제: {temp_path}")
                except Exception as e:
                    logging.warning(f"[ChatGPT-PRECHECK] 임시 파일 삭제 실패: {e}")

        except Exception as e:
            logging.error(f"[ChatGPT-PRECHECK] 사전 검사 중 오류: {e}")
            return {"blocked": False, "reason": f"사전 검사 오류: {str(e)}"}