#!/usr/bin/env python3
"""
Cursor 애플리케이션 어댑터
- NameTab(MCP) → WarmStream(표준) 우선 처리
- 같은 '세션'에서 NameTab을 한 번이라도 보면 그 세션은 MCP 모드로 고정
  → MCP 세션의 WarmStream은 항상 파싱하지 않음(중복 로그 방지)
"""
import re
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Tuple, List
from mitmproxy import http

from .mcp_parser import MCPParser

# WarmStream/드라이런 엔드포인트 (비-MCP)
WARM_ENDPOINT_KEYWORDS = (
    "WarmStreamUnifiedChatWithTools",
    "GetPromptDryRun",
)

# 세션 상태 보존 기간 (메모리 관리용). MCP 감지 후 이 시간 내 WarmStream은 항상 무시.
# 실제로는 NameTab이 먼저 오고 WarmStream이 몇 분 뒤 와도 중복 안 남도록 넉넉히.
SESSION_TTL_SECONDS = 60 * 60  # 1시간

# 세션 캐시 상한 (메모리 보호). 초과 시 오래된 항목부터 제거.
SESSION_MAX_ENTRIES = 2048


class CursorAdapter:
    def __init__(self, save_log_func: Callable, log_filename: str):
        self.save_log = save_log_func
        self.log_filename = log_filename

        # 세션 상태: key -> ("mcp"|"llm", last_seen_utc)
        self._session_mode: Dict[str, Tuple[str, datetime]] = {}

        print(f"[CURSOR] CursorAdapter 초기화 완료 (로그파일: {log_filename})")

    # ---------- 유틸 ----------
    def _safe_decode(self, content: bytes) -> str:
        try:
            return content.decode('utf-8', errors='ignore')
        except Exception:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    def _get_session_key(self, flow: http.HTTPFlow) -> str:
        """
        세션을 나타내는 키.
        우선순위: x-session-id > x-request-id > (host + x-client-key) > host
        """
        headers = flow.request.headers
        sid = headers.get("x-session-id")
        if sid:
            return f"sid:{sid}"

        rid = headers.get("x-request-id")
        if rid:
            return f"rid:{rid}"

        ckey = headers.get("x-client-key")
        host = flow.request.pretty_host
        if ckey:
            return f"host:{host}|ck:{ckey}"

        return f"host:{host}"

    def _now(self) -> datetime:
        return datetime.utcnow()

    def _cleanup_sessions(self) -> None:
        """TTL 지난 세션 삭제 + 상한 초과 시 LRU 식으로 정리"""
        now = self._now()
        # TTL 정리
        expired_keys = [k for k, (_, seen) in self._session_mode.items()
                        if (now - seen).total_seconds() > SESSION_TTL_SECONDS]
        for k in expired_keys:
            del self._session_mode[k]

        # 상한 정리
        if len(self._session_mode) > SESSION_MAX_ENTRIES:
            # 오래된 순으로 정렬해서 반 절삭
            items: List[Tuple[str, Tuple[str, datetime]]] = sorted(
                self._session_mode.items(), key=lambda kv: kv[1][1]
            )
            remove_n = len(self._session_mode) - SESSION_MAX_ENTRIES
            for k, _ in items[:remove_n]:
                del self._session_mode[k]

    def _touch_session(self, key: str, mode: Optional[str] = None) -> None:
        """
        last_seen 갱신. mode가 주어지면 모드도 갱신.
        - NameTab을 보면 mode="mcp"로 고정.
        """
        now = self._now()
        if key in self._session_mode:
            cur_mode, _ = self._session_mode[key]
            self._session_mode[key] = (mode or cur_mode, now)
        else:
            self._session_mode[key] = (mode or "llm", now)

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
          1) NameTab(MCP) 패킷인지 먼저 검사 → 맞으면 프롬프트 추출/로깅, 세션 모드 'mcp'로 마킹, WarmStream은 동일 세션에서 항상 무시
          2) 그 외 WarmStream 패킷:
               - 세션 모드가 'mcp'면 무조건 스킵 (중복 방지)
               - 아니면(=비-MCP) 프롬프트 추출/로깅
        """
        print(f"[CURSOR] process_request 호출: {flow.request.pretty_host}{flow.request.path[:50]}")
        self._cleanup_sessions()
        session_key = self._get_session_key(flow)
        print(f"[CURSOR] 세션 키: {session_key}")

        # 1) NameTab 우선
        if MCPParser.is_mcp_flow(flow):
            print(f"[CURSOR] MCP 플로우 감지")
            prompt = MCPParser.extract_prompt(flow)
            if prompt and prompt.strip():
                # 세션을 MCP 모드로 '고정'
                print(f"[CURSOR] MCP 프롬프트 추출 성공: {prompt[:50]}")
                self._touch_session(session_key, mode="mcp")
                self._write_log(flow, prompt, interface="mcp")
            else:
                # 프롬프트가 비어도 MCP 플래그는 남겨 스킵 정책 유지
                print(f"[CURSOR] MCP 프롬프트 비어있음")
                self._touch_session(session_key, mode="mcp")
            return

        # 2) WarmStream (비-MCP 경로)
        if self._is_warm_flow(flow):
            print(f"[CURSOR] WarmStream 플로우 감지")
            mode, _ = self._session_mode.get(session_key, ("llm", self._now()))
            # MCP 세션이면 WarmStream은 항상 스킵
            if mode == "mcp":
                print(f"[CURSOR] MCP 세션이므로 WarmStream 스킵")
                self._touch_session(session_key)  # last_seen만 갱신
                return

            # 비-MCP 세션이면 레거시 추출
            print(f"[CURSOR] 레거시 프롬프트 추출 시도")
            legacy_prompt = self._extract_prompt_legacy(flow)
            if legacy_prompt and legacy_prompt.strip():
                print(f"[CURSOR] 레거시 프롬프트 추출 성공: {legacy_prompt[:50]}")
                self._touch_session(session_key, mode="llm")
                self._write_log(flow, legacy_prompt, interface="llm")
            else:
                print(f"[CURSOR] 레거시 프롬프트 추출 실패 또는 비어있음")
        else:
            print(f"[CURSOR] MCP도 WarmStream도 아님, 무시")

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
        self.save_log(entry, self.log_filename)