#!/usr/bin/env python3
"""
API 트래픽 로거 - 최종 버전
- 여러 Cursor URL을 모두 지원하고, 사용자의 실제 프롬프트만 정확히 추출
"""
import json
import re
from pathlib import Path
from datetime import datetime
from mitmproxy import http
from typing import Dict, Any

class APITrafficLogger:
    def __init__(self):
        self.base_dir = Path.home() / ".llm_proxy"
        self.json_log_file = self.base_dir / "llm_api_requests.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        print("\n[INFO] 최종 버전 API 트래픽 로거가 시작되었습니다.")
        print(f"[INFO] 로그 파일: {self.json_log_file}")
        print(f"[INFO] 자동 프롬프트 추출을 시작합니다.\n")

    def _safe_decode(self, content: bytes) -> str:
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    def _save_log(self, entry: Dict[str, Any]):
        try:
            logs = []
            if self.json_log_file.exists():
                try:
                    logs = json.loads(self.json_log_file.read_text(encoding='utf-8'))
                    if not isinstance(logs, list): logs = []
                except:
                    logs = []
            
            logs.append(entry)
            logs = logs[-200:]
            
            self.json_log_file.write_text(
                json.dumps(logs, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )
        except Exception as e:
            print(f"\n[CRITICAL] 로그 저장 실패: {e}\n")

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url
        prompt = None

        # [핵심 수정] 더 유연하고 정확한 URL 조건문으로 변경
        if "api2.cursor.sh/aiserver.v1.ChatService" in url and \
           ("WarmStreamUnifiedChatWithTools" in url or "GetPromptDryRun" in url):
            
            raw_body_str = self._safe_decode(flow.request.content)
            
            # [핵심 수정] 가장 정확도가 높은 프롬프트 추출 로직 적용
            # '{"root":'를 기준으로 잘라, 마지막 조각에서만 text를 찾음
            parts = raw_body_str.split('{"root":')
            
            if len(parts) > 1:
                last_part = parts[-1]
                text_matches = re.findall(r'"text":"((?:[^"\\]|\\.)*)"', last_part)
                
                if text_matches:
                    # 마지막 사용자 프롬프트 블록의 첫 번째 text가 실제 입력값임
                    # prompt = text_matches[0].encode('latin1').decode('unicode-escape', errors='ignore')
                    prompt = text_matches[0]

        # 프롬프트가 성공적으로 추출되고, 내용이 비어있지 않은 경우에만 로그 기록
        if prompt and prompt.strip():
            print(f"[PROMPT] {host} | {prompt}")
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "host": host,
                "url": url,
                "prompt": prompt,
            }
            self._save_log(log_entry)

# mitmproxy가 이 애드온을 로드할 수 있도록 전역 변수로 설정
addons = [APITrafficLogger()]