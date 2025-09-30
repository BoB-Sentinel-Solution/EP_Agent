#!/usr/bin/env python3
"""
LLM 파일 처리 관리자

여러 LLM별 파일 처리 프로세서를 관리하고,
적절한 프로세서를 선택하여 파일 처리를 수행합니다.
"""

import logging
from typing import Dict, Any, Optional, List
from mitmproxy import http

from .processors import BaseLLMProcessor, ChatGPTProcessor
from security.block_handler import create_block_response

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LLMFileManager:
    """LLM 파일 처리 통합 관리자"""

    def __init__(self):
        self.processors: Dict[str, BaseLLMProcessor] = {}
        self._initialize_processors()
        logging.info(f"LLM 파일 매니저 초기화 완료 (프로세서 수: {len(self.processors)})")

    def _initialize_processors(self):
        """사용 가능한 모든 프로세서 초기화"""
        try:
            # ChatGPT 프로세서 등록
            chatgpt_processor = ChatGPTProcessor()
            self.processors[chatgpt_processor.name.lower()] = chatgpt_processor

            # TODO: 추후 다른 LLM 프로세서들 추가
            # claude_processor = ClaudeProcessor()
            # self.processors[claude_processor.name.lower()] = claude_processor

            # gemini_processor = GeminiProcessor()
            # self.processors[gemini_processor.name.lower()] = gemini_processor

            logging.info(f"초기화된 프로세서: {list(self.processors.keys())}")

        except Exception as e:
            logging.error(f"프로세서 초기화 중 오류: {e}")

    def get_processor_for_host(self, host: str) -> Optional[BaseLLMProcessor]:
        """호스트에 적합한 프로세서 반환"""
        for processor in self.processors.values():
            if processor.can_handle(host):
                return processor
        return None

    def is_file_upload_request(self, flow: http.HTTPFlow) -> bool:
        """어떤 LLM의 파일 업로드 요청인지 확인"""
        processor = self.get_processor_for_host(flow.request.pretty_host)
        if processor:
            return processor.is_file_upload_request(flow)
        return False

    def get_processor_name_for_host(self, host: str) -> Optional[str]:
        """호스트에 해당하는 프로세서 이름 반환"""
        processor = self.get_processor_for_host(host)
        return processor.name if processor else None




    def process_upload_request_precheck(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        업로드 요청을 사전 차단하기 위한 OCR 검사 (핵심 메서드)

        Args:
            flow: mitmproxy HTTP 플로우 (업로드 요청)

        Returns:
            처리 결과 또는 None (파일 요청이 아닌 경우)
        """
        processor = self.get_processor_for_host(flow.request.pretty_host)
        if not processor:
            return None

        # 파일 데이터 추출 (한 번만 수행)
        file_data = processor.extract_file_from_upload_request(flow)
        if not file_data:
            return None

        processor_name = processor.name
        logging.info(f"[{processor_name}] 파일 업로드 사전 검사 시작")

        # 사전 검사 수행 (파일 데이터 전달)
        if hasattr(processor, 'process_upload_request_precheck'):
            result = processor.process_upload_request_precheck(flow, file_data)

            # 결과에 프로세서 정보 추가
            if result:
                result["processor"] = processor_name
                result["upload_url"] = flow.request.pretty_url

            return result
        else:
            logging.warning(f"[{processor_name}] 프로세서에 사전 검사 메서드가 없음")
            return {"blocked": False, "reason": "사전 검사 메서드 없음"}



    def cleanup_all_temp_files(self, max_age_hours: int = 24):
        """모든 프로세서의 임시 파일 정리"""
        for processor in self.processors.values():
            try:
                processor.cleanup_temp_files(max_age_hours)
            except Exception as e:
                logging.warning(f"[{processor.name}] 임시 파일 정리 실패: {e}")

    def get_supported_hosts(self) -> List[str]:
        """모든 프로세서가 지원하는 호스트 목록"""
        all_hosts = []
        for processor in self.processors.values():
            all_hosts.extend(processor.get_supported_hosts())
        return list(set(all_hosts))  # 중복 제거

    def get_processor_stats(self) -> Dict[str, Dict[str, Any]]:
        """각 프로세서의 상태 정보 반환"""
        stats = {}
        for name, processor in self.processors.items():
            stats[name] = {
                "name": processor.name,
                "supported_hosts": processor.get_supported_hosts(),
                "initialized": hasattr(processor, 'ocr_engine') and processor.ocr_engine is not None
            }
        return stats