#!/usr/bin/env python3
"""
Cursor 애플리케이션 어댑터
- NameTab(MCP) → WarmStream(표준) 우선순위 처리
- 같은 세션에서 NameTab이 감지되면 일정 시간(기본 15s) WarmStream은 프롬프트 파싱을 시도하지 않음
"""
import re
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict
from mitmproxy import http

from .mcp_parser import MCPParser

# WarmStream/드라이런 엔드포인트 (비-MCP)
WARM_ENDPOINT_KEYWORDS = (
    "WarmStreamUnifiedChatWithTools",
    "GetPromptDryRun",
)

MCP_TTL_SECONDS = 15  # 같은 세션에서 NameTab 본 뒤 이 시간 동안은 WarmStream 파싱 시도 안 함

class CursorAdapter:
    def __init__(self, save_log_func: Callable, log_filename: str):
        self.save_log = save_log_func
        self.log_filename = log_filename
        # 최근 NameTab을 본 세션(혹은 호스트) → 만료시각
        self._mcp_recent: Dict[str, datetime] = {}

    # ---------- 유틸 ----------
    def _safe_decode(self, content: bytes) -> str:
        try:
            return content.decode('utf-8', errors='ignore')
        except Exception:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    def _get_session_key(self, flow: http.HTTPFlow) -> str:
        """
        세션을 나타내는 키. 우선순위: x-session-id > x-request-id > Host
        """
        sid = flow.request.headers.get("x-session-id")
        if sid:
            return f"sid:{sid}"
        rid = flow.request.headers.get("x-request-id")
        if rid:
            return f"rid:{rid}"
        return f"host:{flow.request.pretty_host}"

    def _cleanup_expired(self) -> None:
        now = datetime.utcnow()
        expired = [k for k, until in self._mcp_recent.items() if until < now]
        for k in expired:
            del self._mcp_recent[k]

    def _mark_mcp_seen(self, session_key: str) -> None:
        self._mcp_recent[session_key] = datetime.utcnow() + timedelta(seconds=MCP_TTL_SECONDS)

    def _name_tab_first(self, flow: http.HTTPFlow) -> Optional[str]:
        """
        1) NameTab(MCP)인지 먼저 확인 → 추출 성공 시 프롬프트 반환
        2) 아니면 None
        """
        if MCPParser.is_mcp_flow(flow):
            prompt = MCPParser.extract_prompt(flow)
            if prompt and prompt.strip():
                # 이 세션은 MCP 환경으로 간주
                self._mark_mcp_seen(self._get_session_key(flow))
                return prompt
        return None

    def _is_warm_flow(self, flow: http.HTTPFlow) -> bool:
        url = flow.request.pretty_url
        return any(k in url for k in WARM_ENDPOINT_KEYWORDS)

    def _extract_prompt_legacy(self, flow: http.HTTPFlow) -> Optional[str]:
        """비-MCP(표준) WarmStream 계열에서 프롬프트 추출"""
        if not self._is_warm_flow(flow):
            return None
        raw = self._safe_decode(flow.request.content)
        parts = raw.split('{"root":')
        if len(parts) < 2:
            return None
        last_json = '{"root":' + parts[-1]
        matches = re.findall(r'"text":"((?:[^"\\]|\\.)*)"', last_json)
        return matches[0] if matches else None

    # ---------- mitmproxy entry ----------
    def process_request(self, flow: http.HTTPFlow):
        """
        우선순위:
          A) NameTab(MCP) 패킷이면 → MCP로 로깅 (interface="mcp") 후 리턴
          B) 그 외 WarmStream 패킷이면:
               - 최근 같은 세션에서 NameTab을 봤으면(=MCP환경) 파싱 시도 안 함
               - 그렇지 않으면(=비-MCP) WarmStream에서 프롬프트 추출 후 로깅
        """
        self._cleanup_expired()
        host = flow.request.pretty_host
        session_key = self._get_session_key(flow)

        # A) NameTab 먼저 확인/로깅
        mcp_prompt = self._name_tab_first(flow)
        if mcp_prompt:
            self._write_log(flow, mcp_prompt, interface="mcp")
            return

        # B) WarmStream
        if self._is_warm_flow(flow):
            # 같은 세션에서 방금 NameTab을 봤다면 WarmStream은 (MCP환경에서) 프롬프트가 없음
            if session_key in self._mcp_recent:
                # MCP 모드로 간주되므로 스킵
                return

            # MCP 모드가 아니라면(=비-MCP), WarmStream에서 추출 시도
            legacy_prompt = self._extract_prompt_legacy(flow)
            if legacy_prompt and legacy_prompt.strip():
                self._write_log(flow, legacy_prompt, interface="llm")

    # ---------- 로깅 ----------
    def _write_log(self, flow: http.HTTPFlow, prompt: str, interface: str):
        print(f"[LOG/CURSOR] 인터페이스: {interface} | 호스트: {flow.request.pretty_host} | 프롬프트: {prompt}")
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": flow.request.pretty_host,
            "url": flow.request.pretty_url,
            "prompt": prompt,
            "interface": interface,
        }
        # MCP/표준을 파일로 분리하고 싶으면 아래 한 줄을 바꾸세요.
        # filename = self.log_filename if interface == "standard" else "cursor_requests_mcp.json"
        filename = self.log_filename
        self.save_log(entry, filename)
