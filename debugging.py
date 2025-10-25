#!/usr/bin/env python3
"""
트래픽 로거 - LLM API 트래픽(HTTP, WebSocket) 감지 및 디버깅 JSON 저장
"""

import json
import base64
from pathlib import Path
from mitmproxy import http, websocket # websocket 타입을 사용하기 위해 추가
from datetime import datetime

DEBUG_LOG_FILE = Path.home() / ".llm_proxy" / "debugging.json"

class LLMSelectiveLogger:
    """LLM 트래픽 디버깅 로거 (WebSocket 지원 추가)"""

    def __init__(self):
        #모니터링할 호스트 목록
        self.LLM_HOSTS = {
            "chatgpt.com", "claude.ai", "gemini.google.com", 
            "chat.deepseek.com", "groq.com", "api.groq.com",
            "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
            "oaiusercontent.com"
        }
        

        self.LLM_HOST_PATTERNS = {
            ".cursor.sh", 
        }

    def _is_target_host(self, host: str) -> bool:
        """호스트 이름이 모니터링 대상인지 확인하는 내부 헬퍼 함수"""
        # 정확한 매칭
        if host in self.LLM_HOSTS:
            return True
        # 부분 문자열 매칭 (서브도메인 지원)
        for target in self.LLM_HOSTS:
            if target in host:
                return True
        # 패턴 매칭
        for pattern in self.LLM_HOST_PATTERNS:
            if pattern in host:
                return True
        return False

    def _save_log(self, log_entry: dict):
        """로그 항목을 JSON 파일에 저장하는 공통 함수"""
        try:
            DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            logs = []
            if DEBUG_LOG_FILE.exists():
                content = DEBUG_LOG_FILE.read_text(encoding="utf-8").strip()
                if content:
                    try:
                        logs = json.loads(content)
                    except json.JSONDecodeError:
                        logs = []
            
            logs.append(log_entry)
            if len(logs) > 100:
                logs = logs[-100:]
            
            DEBUG_LOG_FILE.write_text(json.dumps(logs, indent=2, ensure_ascii=False), encoding='utf-8')
        except Exception as e:
            print(f"[ERROR] 로그 저장 실패: {e}")

    def safe_decode_content(self, content: bytes) -> str:
        if not content: return ""
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return f"[BINARY_CONTENT: {len(content)} bytes]"
    
    # --- HTTP Hooks ---
    def request(self, flow: http.HTTPFlow):
        if not self._is_target_host(flow.request.pretty_host): return

        # 파일 업로드 요청인 경우 Base64 인코딩
        is_file_upload = (flow.request.method == "PUT" and "oaiusercontent" in flow.request.pretty_host)

        if is_file_upload:
            # Base64 인코딩 (복구 가능)
            request_body = base64.b64encode(flow.request.content).decode('utf-8') if flow.request.content else ""
            encoding_type = "base64"
        else:
            # 일반 텍스트 (2000자 제한)
            request_body = self.safe_decode_content(flow.request.content)[:2000]
            encoding_type = "utf-8"

        log_entry = {
            "type": "http_request", "time": datetime.now().isoformat(), "host": flow.request.pretty_host,
            "path": flow.request.path, "method": flow.request.method, "request_headers": dict(flow.request.headers),
            "request_body": request_body,
            "content_size": len(flow.request.content) if flow.request.content else 0,
            "encoding": encoding_type
        }
        print(f"[DEBUG] HTTP Request: {log_entry['method']} {log_entry['host']}{log_entry['path']} ({log_entry['content_size']} bytes, {encoding_type})")
        self._save_log(log_entry)

    def response(self, flow: http.HTTPFlow):
        #if not self._is_target_host(flow.request.pretty_host) or not flow.response: return
        log_entry = {
            "type": "http_response", "time": datetime.now().isoformat(), "host": flow.request.pretty_host,
            "path": flow.request.path, "method": flow.request.method, "response_status": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": self.safe_decode_content(flow.response.content)[:2000]
        }
        print(f"[DEBUG] HTTP Response: {log_entry['response_status']} for {log_entry['host']}{log_entry['path']}")
        self._save_log(log_entry)

    # --- WebSocket Hooks ---
    def websocket_handshake(self, flow: http.HTTPFlow):
        if not self._is_target_host(flow.request.pretty_host): return
        log_entry = {
            "type": "websocket_handshake", "time": datetime.now().isoformat(), "host": flow.request.pretty_host,
            "path": flow.request.path, "headers": dict(flow.request.headers)
        }
        print(f"[DEBUG] WebSocket Handshake to: {log_entry['host']}{log_entry['path']}")
        self._save_log(log_entry)

    def websocket_message(self, flow: websocket.WebSocketData): # <--- 여기가 수정되었습니다!
        if not self._is_target_host(flow.client_conn.peername[0]): return
        message = flow.messages[-1]
        direction = "Client -> Server" if message.from_client else "Server -> Client"
        
        log_entry = {
            "type": "websocket_message", "time": datetime.now().isoformat(), "host": flow.client_conn.peername[0],
            "direction": direction, "message_content": self.safe_decode_content(message.content)[:2000]
        }
        print(f"[DEBUG] WebSocket Message: {log_entry['direction']} on {log_entry['host']}")
        self._save_log(log_entry)

addons = [LLMSelectiveLogger()]