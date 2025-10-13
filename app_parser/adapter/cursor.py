#!/usr/bin/env python3
"""
Cursor 애플리케이션 어댑터 (수정)
- NameTab(MCP)과 WarmStream(표준)을 모두 처리
- 중복 방지: 같은 프롬프트가 짧은 시간 내에 반복되면 스킵
"""
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, List, Any
from mitmproxy import http

from .mcp_parser import MCPParser

# WarmStream/드라이런 엔드포인트 (비-MCP)
WARM_ENDPOINT_KEYWORDS = (
    "WarmStreamUnifiedChatWithTools",
    "GetPromptDryRun",
)

# 중복 방지 시간 윈도우 (초) - 이 시간 내 같은 프롬프트는 스킵
DEDUP_WINDOW_SECONDS = 5

# 캐시 상한 (메모리 보호)
CACHE_MAX_ENTRIES = 1024


class CursorAdapter:
    def __init__(self):
        # 최근 처리한 프롬프트 캐시: prompt_hash -> (interface, timestamp)
        self._recent_prompts: Dict[str, Tuple[str, datetime]] = {}
        print(f"[CURSOR] CursorAdapter 초기화 완료")

    # ---------- 유틸 ----------
    def _safe_decode(self, content: bytes) -> str:
        try:
            return content.decode('utf-8', errors='ignore')
        except Exception:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    def _now(self) -> datetime:
        return datetime.utcnow()

    def _prompt_hash(self, prompt: str) -> str:
        """프롬프트의 간단한 해시 (앞 100자 + 길이)"""
        return f"{prompt[:100]}|{len(prompt)}"

    def _cleanup_cache(self) -> None:
        """오래된 캐시 항목 정리"""
        now = self._now()
        # 윈도우 시간 지난 항목 삭제
        expired = [k for k, (_, ts) in self._recent_prompts.items()
                   if (now - ts).total_seconds() > DEDUP_WINDOW_SECONDS]
        for k in expired:
            del self._recent_prompts[k]

        # 상한 초과 시 절반 삭제
        if len(self._recent_prompts) > CACHE_MAX_ENTRIES:
            items = sorted(self._recent_prompts.items(), key=lambda x: x[1][1])
            for k, _ in items[:len(items)//2]:
                del self._recent_prompts[k]

    def _is_duplicate(self, prompt: str, interface: str) -> bool:
        """
        최근에 같은 프롬프트를 처리했는지 확인
        - 같은 프롬프트가 DEDUP_WINDOW_SECONDS 내에 있으면 중복으로 간주
        """
        prompt_key = self._prompt_hash(prompt)
        now = self._now()

        if prompt_key in self._recent_prompts:
            prev_interface, prev_time = self._recent_prompts[prompt_key]
            time_diff = (now - prev_time).total_seconds()
            
            if time_diff < DEDUP_WINDOW_SECONDS:
                print(f"[CURSOR] 중복 프롬프트 감지 (이전: {prev_interface}, {time_diff:.1f}초 전)")
                return True

        # 새 프롬프트이거나 윈도우 지남 - 캐시 업데이트
        self._recent_prompts[prompt_key] = (interface, now)
        return False

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

    # ---------- 프롬프트 추출 (디스패처용) ----------
    def extract_prompt(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트 추출 및 중복 체크
        반환: {"prompt": str, "interface": str} 또는 None

        우선순위:
          1) NameTab(MCP) 패킷 체크 → 프롬프트 추출, interface="mcp"
          2) WarmStream 패킷 체크 → 프롬프트 추출, interface="llm"
          3) 중복 체크: 같은 프롬프트가 짧은 시간 내 반복되면 스킵
        """
        print(f"[CURSOR] extract_prompt 호출: {flow.request.pretty_host}{flow.request.path[:50]}")
        self._cleanup_cache()

        # 1) NameTab (MCP) 우선
        if MCPParser.is_mcp_flow(flow):
            print(f"[CURSOR] MCP 플로우 감지")
            prompt = MCPParser.extract_prompt(flow)
            if prompt and prompt.strip():
                print(f"[CURSOR] MCP 프롬프트 추출 성공: {prompt[:50]}")
                
                # 중복 체크
                if self._is_duplicate(prompt, "mcp"):
                    return None
                
                return {"prompt": prompt, "interface": "mcp"}
            else:
                print(f"[CURSOR] MCP 프롬프트 비어있음")
                return None

        # 2) WarmStream (표준 LLM)
        if self._is_warm_flow(flow):
            print(f"[CURSOR] WarmStream 플로우 감지")
            legacy_prompt = self._extract_prompt_legacy(flow)
            
            if legacy_prompt and legacy_prompt.strip():
                print(f"[CURSOR] LLM 프롬프트 추출 성공: {legacy_prompt[:50]}")
                
                # 중복 체크
                if self._is_duplicate(legacy_prompt, "llm"):
                    return None
                
                return {"prompt": legacy_prompt, "interface": "llm"}
            else:
                print(f"[CURSOR] LLM 프롬프트 추출 실패 또는 비어있음")
                return None
        else:
            print(f"[CURSOR] MCP도 WarmStream도 아님, 무시")
            return None