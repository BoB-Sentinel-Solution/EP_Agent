#!/usr/bin/env python3
"""
Cursor 애플리케이션 어댑터 (독립 버전)
- 더 이상 다른 파일에 의존하지 않습니다.
- 생성될 때 로깅 기능을 주입받아 사용합니다.
"""
import re
import json
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Optional, Dict, Any, Callable

# BaseAdapter 상속을 제거하고, 순수 클래스로 만듭니다.
class CursorAdapter:
    def __init__(self, save_log_func: Callable, log_filename: str):
        """
        CursorAdapter를 초기화합니다.
        
        Args:
            save_log_func (Callable): 로그 저장을 처리할 함수 (app_main에서 전달받음).
            log_filename (str): 로그를 저장할 파일 이름 (app_main에서 전달받음).
        """
        self.save_log = save_log_func
        self.log_filename = log_filename

    def _safe_decode(self, content: bytes) -> str:
        """바이트 콘텐츠를 문자열로 안전하게 디코딩합니다."""
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    def extract_prompt(self, flow: http.HTTPFlow) -> Optional[str]:
        """Cursor API에서 사용자 프롬프트를 추출합니다."""
        url = flow.request.pretty_url
        if not ("WarmStreamUnifiedChatWithTools" in url or "GetPromptDryRun" in url):
            return None

        raw_body_str = self._safe_decode(flow.request.content)
        parts = raw_body_str.split('{"root":')
        
        if len(parts) > 1:
            last_json_part = parts[-1]
            text_matches = re.findall(r'"text":"((?:[^"\\]|\\.)*)"', last_json_part)
            
            if text_matches:
                prompt = text_matches[0]
                return prompt
        return None
    
    def process_request(self, flow: http.HTTPFlow):
        """
        프롬프트를 추출하고, 주입받은 로그 함수를 사용해 파일에 저장합니다.
        """
        prompt = self.extract_prompt(flow)
        
        if prompt and prompt.strip():
            host = flow.request.pretty_host
            print(f"[LOG/CURSOR] 호스트: {host} | 프롬프트: {prompt}")
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "host": host,
                "url": flow.request.pretty_url,
                "prompt": prompt,
                "adapter": "CursorAdapter"
            }
            
            # 생성자에서 받아온 함수를 사용해 로그를 저장합니다.
            self.save_log(log_entry, self.log_filename)