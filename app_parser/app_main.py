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

from app_parser.adapter.cursor import CursorAdapter
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
            ".cursor.sh": CursorAdapter(),
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
        3. 변조를 위해 "원본 JSON(dict)"을 "context"에 추가하여 반환합니다.
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
        
        if extracted_data and "context" in extracted_data:
            # 3. [중요] 변조를 위해 원본 body_json을 context에 추가 (LLM과 통일: request_data)
            extracted_data["context"]["request_data"] = body_json
            
        # print(f"[APP_MAIN] 프롬프트 추출 결과: {extracted_data is not None}")
        return extracted_data

    # [!!! 함수 수정 !!!]
    def modify_request(self, flow: http.HTTPFlow, new_prompt: str, extracted_data: Dict[str, Any]):
        """
        [리팩토링]
        '부수 효과'를 담당합니다.
        1. 어댑터(순수 함수)를 호출하여 "변조된 bytes"를 받습니다.
        2. "변조된 bytes"를 'flow' 객체에 적용합니다.
        """
        host = flow.request.pretty_host
        adapter = self._get_adapter(host)
        
        if not adapter or not hasattr(adapter, 'modify_request_data'):
            print(f"[APP_MAIN] {host}에 대한 변조기(modify_request_data)를 찾을 수 없음")
            return

        # 1. 컨텍스트에서 'request_data'와 'adapter_context'를 분리 (LLM과 통일)
        context_data = extracted_data.get("context", {})
        request_data = context_data.pop("request_data", None)  # request_data를 꺼냄

        if not request_data:
            print(f"[APP_MAIN] 변조 실패: 컨텍스트에 원본 'request_data'가 없음")
            return

        # 2. 어댑터(순수 함수) 호출: (dict, context, str) -> bytes
        new_bytes = adapter.modify_request_data(request_data, context_data, new_prompt)

        # 3. 'flow' 객체에 "부수 효과" 적용
        if new_bytes:
            flow.request.content = new_bytes
            flow.request.headers["Content-Length"] = str(len(new_bytes))
            print(f"[APP_MAIN] {host}의 프롬프트 변조 완료.")
        else:
            print(f"[APP_MAIN] {host}의 프롬프트 변조 실패 (adapter가 None 반환)")