#!/usr/bin/env python3
"""
트래픽 로거 - LLM API 트래픽 감지 및 디버깅 JSON 저장
"""

import json
from pathlib import Path
from mitmproxy import http
from datetime import datetime

DEBUG_LOG_FILE = Path.home() / ".llm_proxy" / "debugging.json"

class LLMSelectiveLogger:
    """LLM 트래픽 디버깅 로거"""

    # 로깅할 LLM 서비스 호스트 목록
    LLM_HOSTS = {
        "api.openai.com", "chatgpt.com",
        "api.anthropic.com", "claude.ai",
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com","gemini.google.com",
        "api.groq.com", "api.cohere.ai", "api.deepseek.com"
    }

    def is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """요청 호스트가 지정된 LLM 목록에 있는지 확인"""
        return flow.request.pretty_host in self.LLM_HOSTS

    def safe_decode_content(self, content: bytes) -> str:
        """바이트 컨텐츠를 안전하게 디코딩"""
        if not content:
            return ""
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return f"[BINARY_CONTENT: {len(content)} bytes]"

    def response(self, flow: http.HTTPFlow):
        """응답 완료 시 LLM 요청인지 확인하고 상세 정보 출력 및 JSON 저장"""
        if not self.is_llm_request(flow) or not flow.response:
            return

        host = flow.request.pretty_host
        path = flow.request.path
        method = flow.request.method

        request_body = self.safe_decode_content(flow.request.content)
        response_body = self.safe_decode_content(flow.response.content)

        log_entry = {
            "time": datetime.now().isoformat(),
            "host": host,
            "path": path,
            "method": method,
            "request_headers": dict(flow.request.headers),
            "response_headers": dict(flow.response.headers),
            "request_body": request_body[:1000],
            "response_body": response_body[:1000],
            "content_type": flow.request.headers.get("content-type", ""),
            "response_status": flow.response.status_code
        }

        # 콘솔 출력
        print(f"[DEBUG] {log_entry}")
        print("="*80)

        # JSON 파일 저장
        try:
            DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            logs = []
            if DEBUG_LOG_FILE.exists():
                with open(DEBUG_LOG_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        logs = json.loads(content)
            logs.append(log_entry)
            # 최근 100개 로그만 유지
            if len(logs) > 100:
                logs = logs[-100:]
            with open(DEBUG_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ERROR] 로그 저장 실패: {e}")

addons = [LLMSelectiveLogger()]
