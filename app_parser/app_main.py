#!/usr/bin/env python3
"""
통합 LLM 트래픽 로거 - 메인 애플리케이션 (의존성 주입 버전)
- 순환 참조 문제를 해결하기 위해 어댑터에 로그 기능을 직접 주입합니다.
"""
import json
import re
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Dict, Any, Optional, Set

from app_parser.adapter.vscode import VSCodeCopilotAdapter


# -------------------------------
# 유틸리티 클래스 
# -------------------------------
class FileUtils:
    @staticmethod
    def is_supported_file(filename: str) -> bool:
        ext = Path(filename).suffix.lower()
        supported_types = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.pdf', '.txt', '.doc', '.docx'}
        return ext in supported_types

    @staticmethod
    def safe_filename(original_name: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(original_name).stem
        ext = Path(original_name).suffix
        safe_stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem)[:50]
        return f"{timestamp}_{safe_stem}{ext}"

# -------------------------------
# 메인 통합 로거
# -------------------------------
class UnifiedAppLogger:
    def __init__(self):
        """디렉터리를 초기화하고, 감시할 호스트 목록과 어댑터를 설정합니다."""
        self.base_dir = Path.home() / ".llm_proxy"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # App/MCP 호스트 키워드 (부분 매칭)
        self.API_HOST_KEYWORDS: Set[str] = {
            "cursor.sh", "localhost", "127.0.0.1",
            
            #VSCode Copilot
            "api.individual.githubcopilot.com",
            "copilot", "githubusercontent.com", "github.com"
        }
        
        # 어댑터 생성 (프롬프트 추출만 수행)
        self.adapters: Dict[str, Any] = {
            "copilot" : VSCodeCopilotAdapter(),
            ".github.com": VSCodeCopilotAdapter(),
            "api.individual.githubcopilot.com" : VSCodeCopilotAdapter()
        }
        
        print("\n[INFO] App/MCP 핸들러가 시작되었습니다.")
        print(f"[INFO] 감시 호스트 키워드: {', '.join(sorted(self.API_HOST_KEYWORDS))}")
        print(f"[INFO] 로드된 어댑터: {', '.join(self.adapters.keys())}\n")

    def _get_adapter(self, host: str) -> Optional[Any]:
        """주어진 호스트에 맞는 어댑터를 찾습니다."""
        for host_keyword, adapter in self.adapters.items():
            if host_keyword in host:
                return adapter
        return None

    def extract_prompt_only(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        [리팩토링]
        1. flow에서 JSON(dict)을 파싱합니다.
        2. 어댑터(순수 함수)를 호출하여 "prompt"와 "context"를 추출합니다.
        3. LLM 핸들러와 통일된 형식으로 반환합니다.
        """
        host = flow.request.pretty_host
        if not any(keyword in host for keyword in self.API_HOST_KEYWORDS):
            return None

        adapter = self._get_adapter(host)
        if not adapter:
            return None

        # 1. 어댑터를 사용해 'flow' -> 'json' 파싱 (유일한 I/O)
        if not hasattr(adapter, 'parse_flow_to_json'):
             print(f"[APP_MAIN] 어댑터에 'parse_flow_to_json'이 없음")
             return None

        body_json = adapter.parse_flow_to_json(flow)
        if not body_json:
            # print(f"[APP_MAIN] {host} 요청 파싱 실패 (대상이 아니거나, JSON 오류)")
            return None

        # 2. 어댑터를 사용해 'json' -> 'prompt', 'context' 추출 (순수 함수)
        if not hasattr(adapter, 'extract_prompt'):
            print(f"[APP_MAIN] 어댑터에 'extract_prompt'가 없음")
            return None

        extracted_data = adapter.extract_prompt(body_json)

        if not extracted_data:
            return None

        # 3. [중요] LLM 핸들러와 통일된 context 구조로 변환
        # LLM 형식: {"prompt": str, "attachment": {...}, "context": {"request_data": dict, "content_type": str, "host": str}}
        content_type = flow.request.headers.get("content-type", "").lower()

        # 기존 context 정보는 유지하되, 통일된 필드 추가
        if "context" not in extracted_data:
            extracted_data["context"] = {}

        extracted_data["context"]["request_data"] = body_json
        extracted_data["context"]["content_type"] = content_type
        extracted_data["context"]["host"] = host

        # attachment 필드가 없으면 추가 (LLM과 통일)
        if "attachment" not in extracted_data:
            extracted_data["attachment"] = {"format": None, "data": None}

        # print(f"[APP_MAIN] 프롬프트 추출 결과: {extracted_data is not None}")
        return extracted_data

    # [!!! 함수 수정 !!!]
    def modify_request(self, flow: http.HTTPFlow, modified_prompt: str, extracted_data: Dict[str, Any]):
        """
        [리팩토링 - LLM 핸들러와 통일]
        '부수 효과'를 담당합니다.
        1. 어댑터(순수 함수)를 호출하여 "(bool, bytes)" 튜플을 받습니다.
        2. "변조된 bytes"를 'flow' 객체에 적용합니다.
        """
        try:
            print(f"\n{'='*80}")
            print(f"[APP_MAIN DEBUG] modify_request 호출됨")

            # context에서 저장된 원본 데이터 가져오기
            context = extracted_data.get("context", {})
            request_data = context.get("request_data")
            content_type = context.get("content_type", "")
            host = context.get("host", flow.request.pretty_host)

            print(f"[APP_MAIN DEBUG] host: {host}")
            print(f"[APP_MAIN DEBUG] modified_prompt 길이: {len(modified_prompt)}")
            print(f"[APP_MAIN DEBUG] request_data keys: {list(request_data.keys()) if request_data else 'None'}")

            if not request_data:
                print(f"[APP_MAIN] 변조 실패: context에 request_data 없음")
                return

            adapter = self._get_adapter(host)

            if not adapter:
                print(f"[APP_MAIN] {host}에 대한 어댑터를 찾을 수 없음")
                return

            # LLM 핸들러처럼 should_modify 체크 후 변조 수행
            if hasattr(adapter, 'should_modify') and not adapter.should_modify(host, content_type):
                print(f"[APP_MAIN] {host}는 변조 대상이 아님 (should_modify=False)")
                return

            if not hasattr(adapter, 'modify_request_data'):
                print(f"[APP_MAIN] {host} 어댑터에 modify_request_data 메서드가 없음")
                return

            # LLM 핸들러처럼 튜플 언팩
            print(f"[APP_MAIN DEBUG] adapter.modify_request_data 호출 시작...")
            success, modified_content = adapter.modify_request_data(request_data, modified_prompt, host)
            print(f"[APP_MAIN DEBUG] modify_request_data 결과 - success={success}, content_length={len(modified_content) if modified_content else 'None'}")

            if success and modified_content:
                # 요청 본문 수정
                flow.request.content = modified_content

                # 헤더 업데이트
                flow.request.headers["Content-Length"] = str(len(modified_content))

                # Content-Encoding 제거 (있을 경우)
                if "Content-Encoding" in flow.request.headers:
                    del flow.request.headers["Content-Encoding"]

                print(f"[APP_MAIN DEBUG] flow.request.content 변조 전 -> 후 길이: {len(modified_content)}")
                print(f"[APP_MAIN DEBUG] 변조된 내용 미리보기: {modified_content[:200]}...")
                print(f"[APP_MAIN] {host}의 프롬프트 변조 완료.")
                print(f"{'='*80}\n")
            else:
                print(f"[APP_MAIN] {host}의 프롬프트 변조 실패")
                print(f"[APP_MAIN DEBUG] success={success}, modified_content_type={type(modified_content)}")
                print(f"{'='*80}\n")

        except Exception as e:
            print(f"[APP_MAIN] modify_request 오류: {e}")
            import traceback
            traceback.print_exc()
            print(f"{'='*80}\n")