#!/usr/bin/env python3
"""
ChatGPT 파일 처리 프로세서

files.oaiusercontent.com을 통한 ChatGPT 파일 업로드를 감지하고
OCR 처리하여 보안 키워드를 검사합니다.

공통 모듈을 사용하여 다운로드와 OCR 처리를 수행합니다.
"""

import logging
from typing import Dict, Any, Optional, List
from mitmproxy import http

from .base_processor import BaseLLMProcessor
from ..common import FileDownloader
# from ..common import OCRProcessor, FileUtils  # OCR 기능 비활성화

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
            # self.ocr_processor = OCRProcessor(['ko', 'en'])  # OCR 기능 일시 비활성화
            logging.info("ChatGPT 파일 프로세서 초기화 완료 (파일 저장 전용)")
        except Exception as e:
            logging.error(f"ChatGPT 파일 프로세서 초기화 실패: {e}")
            self.file_downloader = None
            # self.ocr_processor = None

    def get_supported_hosts(self) -> List[str]:
        """ChatGPT에서 사용하는 파일 호스트 목록"""
        return ["oaiusercontent.com"]  # 모든 서브도메인 포함

    def is_file_upload_request(self, flow: http.HTTPFlow) -> bool:
        """ChatGPT 파일 업로드 요청인지 확인 (호환성을 위해 유지)"""
        # 실제로는 extract_file_from_upload_request에서 판단하므로 간단한 체크만
        host = flow.request.pretty_host
        method = flow.request.method
        return (self.can_handle(host) and
                method in ["PUT", "POST"] and
                flow.request.content and len(flow.request.content) > 100)



    def extract_file_from_upload_request(self, flow: http.HTTPFlow) -> Optional[bytes]:
        """파일 업로드 요청 감지 및 데이터 추출 (통합 함수)"""
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path
            content = flow.request.content

            # 디버깅: 모든 oaiusercontent.com 요청 확인
            if "oaiusercontent.com" in host:
                content_type = flow.request.headers.get("content-type", "").lower()
                content_size = len(content) if content else 0
                can_handle_result = self.can_handle(host)

                print(f"[ChatGPT-DEBUG]   oaiusercontent.com 요청 분석:")
                print(f"[ChatGPT-DEBUG]   Host: {host}")
                print(f"[ChatGPT-DEBUG]   Method: {method}")
                print(f"[ChatGPT-DEBUG]   Path: {path}")
                print(f"[ChatGPT-DEBUG]   Content-Type: {content_type}")
                print(f"[ChatGPT-DEBUG]   Content-Size: {content_size} bytes")
                print(f"[ChatGPT-DEBUG]   can_handle(): {can_handle_result}")

            # 지원하지 않는 호스트면 None
            if not self.can_handle(host):
                return None

            # 파일 데이터가 없으면 None
            if not content or len(content) < 100:
                return None

            # PUT 방식 파일 업로드 감지
            if method == "PUT":
                logging.info(f"[ChatGPT] PUT 파일 업로드 감지: {len(content)} bytes")
                return content

            # POST 방식 파일 업로드 감지
            if method == "POST":
                content_type = flow.request.headers.get("content-type", "").lower()
                if ("multipart/form-data" in content_type or
                    "image/" in content_type or
                    "application/pdf" in content_type or
                    "application/octet-stream" in content_type):
                    logging.info(f"[ChatGPT] POST 파일 업로드 감지 ({content_type}): {len(content)} bytes")
                    return content

            return None

        except Exception as e:
            logging.error(f"[ChatGPT] 파일 데이터 추출 중 오류: {e}")
            return None





    def process_upload_request_precheck(self, flow: http.HTTPFlow, file_data: bytes = None) -> Dict[str, Any]:
        """업로드 요청 사전 처리 (파일 저장만 수행, OCR 비활성화)"""

        try:
            logging.info("[ChatGPT-PRECHECK] 파일 저장 시작")

            # 1. 파일 데이터는 이미 추출되어 전달됨 (중복 호출 방지)
            if not file_data:
                logging.warning("[ChatGPT-PRECHECK] 파일 데이터가 전달되지 않음")
                return {"blocked": False, "reason": "파일 데이터 없음"}

            # 2. 파일을 다운로드 폴더에 저장
            save_result = self.file_downloader.save_intercepted_file(
                file_data=file_data,
                original_url=flow.request.pretty_url,
                host=flow.request.pretty_host,
                content_type=flow.request.headers.get("content-type", ""),
                method=flow.request.method,
                additional_info={
                    "path": flow.request.path,
                    "user_agent": flow.request.headers.get("user-agent", ""),
                    "request_size": len(flow.request.content) if flow.request.content else 0
                }
            )

            if save_result["success"]:
                logging.info(f"[ChatGPT-PRECHECK] 파일 저장 성공: {save_result['filename']}")
            else:
                logging.warning(f"[ChatGPT-PRECHECK] 파일 저장 실패: {save_result.get('error', 'Unknown')}")

            # 3. OCR 검사는 비활성화됨 - 항상 허용
            # # 임시 파일 생성 및 OCR 처리 (비활성화)
            # temp_file = tempfile.NamedTemporaryFile(...)
            # ocr_result = self.ocr_processor.process_image_with_keywords(temp_path)
            # if ocr_result["blocked"]:
            #     return {"blocked": True, "keyword": ocr_result["keyword"], ...}

            logging.info(f"[ChatGPT-PRECHECK] 파일 업로드 허용 - 파일: {save_result.get('filename', 'Unknown')}")
            return {
                "blocked": False,
                "reason": "OCR 검사 비활성화됨, 파일 저장만 완료",
                "saved_file": save_result.get("filename", "")
            }

        except Exception as e:
            logging.error(f"[ChatGPT-PRECHECK] 처리 중 오류: {e}")
            return {"blocked": False, "reason": f"처리 오류: {str(e)}"}