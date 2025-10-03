#!/usr/bin/env python3
"""
트래픽 로거 - 모든 HTTP 트래픽을 사람이 읽기 쉬운 raw 로그로 저장
사용:
  mitmdump -s this_script.py --set http2=true

로그 파일:
  ~/.llm_proxy/debugging_all.raw
"""

import json
import base64
from pathlib import Path
from mitmproxy import http
from datetime import datetime

DEBUG_LOG_FILE = Path.home() / ".llm_proxy" / "debugging_all.json"
DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

class AllTrafficLogger:
    """모든 HTTP 트래픽 디버깅 로거 (raw 텍스트 출력)"""

    def safe_decode_content(self, content: bytes):
        """바이트 컨텐츠를 안전하게 디코딩.
        텍스트로 디코드 가능하면 (utf-8 replace) 그 텍스트를 반환,
        아니면 ('BINARY', base64_string) 튜플을 반환합니다.
        """
        if not content:
            return ""
        try:
            text = content.decode('utf-8', errors='strict')
            return text
        except Exception:
            # 텍스트로 안전하게 디코딩 불가 -> base64로 저장
            b64 = base64.b64encode(content).decode('ascii')
            return ("[BINARY_BASE64]", b64)

    def _write_block(self, text: str):
        """로그 파일에 텍스트 블록을 append (utf-8)"""
        try:
            with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(text)
                f.flush()
        except Exception as e:
            print(f"[ERROR] 로그 파일 쓰기 실패: {e}")

    def _format_headers(self, headers: dict) -> str:
        out = []
        for k, v in headers.items():
            out.append(f"{k}: {v}")
        return "\n".join(out)

    def request(self, flow: http.HTTPFlow):
        """요청 시점에 모든 요청 로깅 (raw)"""
        try:
            host = flow.request.pretty_host if flow.request else "unknown"
            path = flow.request.path if flow.request else ""
            method = flow.request.method if flow.request else "UNKNOWN"
            headers = dict(flow.request.headers) if flow.request and flow.request.headers else {}
            raw = flow.request.raw_content if getattr(flow.request, "raw_content", None) is not None else flow.request.content
            decoded = self.safe_decode_content(raw)

            ts = datetime.now().isoformat()
            header_block = self._format_headers(headers)

            body_text = ""
            if isinstance(decoded, tuple) and decoded[0] == "[BINARY_BASE64]":
                body_text = "[BINARY - base64]\n" + decoded[1]
            else:
                body_text = decoded if decoded is not None else ""

            block = []
            block.append(f"---- REQUEST [{ts}] ----")
            block.append(f"{method} {host}{path}")
            block.append("Headers:")
            block.append(header_block if header_block else "(none)")
            block.append("Body:")
            block.append(body_text if body_text else "(empty)")
            block.append("\n")  # 빈 줄
            self._write_block("\n".join(block))
            print(f"[DEBUG] Traffic Detected: {method} {host}{path}")
        except Exception as e:
            print(f"[WARN] request 훅 처리 중 예외: {e}")

    def response(self, flow: http.HTTPFlow):
        """응답 완료 시 모든 요청/응답 로깅 (raw)"""
        try:
            if not getattr(flow, "response", None):
                return

            host = flow.request.pretty_host if flow.request else "unknown"
            path = flow.request.path if flow.request else ""
            method = flow.request.method if flow.request else "UNKNOWN"
            req_headers = dict(flow.request.headers) if flow.request and flow.request.headers else {}
            res_headers = dict(flow.response.headers) if flow.response and flow.response.headers else {}
            raw_req = flow.request.raw_content if getattr(flow.request, "raw_content", None) is not None else flow.request.content
            raw_res = flow.response.raw_content if getattr(flow.response, "raw_content", None) is not None else flow.response.content

            decoded_req = self.safe_decode_content(raw_req)
            decoded_res = self.safe_decode_content(raw_res)

            ts = datetime.now().isoformat()

            # format request part (short)
            req_body_text = ""
            if isinstance(decoded_req, tuple) and decoded_req[0] == "[BINARY_BASE64]":
                req_body_text = "[BINARY - base64]\n" + decoded_req[1]
            else:
                req_body_text = decoded_req if decoded_req is not None else ""

            # format response body
            res_body_text = ""
            if isinstance(decoded_res, tuple) and decoded_res[0] == "[BINARY_BASE64]":
                res_body_text = "[BINARY - base64]\n" + decoded_res[1]
            else:
                res_body_text = decoded_res if decoded_res is not None else ""

            block = []
            block.append(f"---- RESPONSE [{ts}] ----")
            block.append(f"{method} {host}{path}")
            block.append(f"Status: {getattr(flow.response, 'status_code', getattr(flow.response, 'status', ''))}")
            block.append("Request Headers:")
            block.append(self._format_headers(req_headers) if req_headers else "(none)")
            block.append("Request Body:")
            block.append(req_body_text if req_body_text else "(empty)")
            block.append("Response Headers:")
            block.append(self._format_headers(res_headers) if res_headers else "(none)")
            block.append("Response Body:")
            block.append(res_body_text if res_body_text else "(empty)")
            block.append("\n")
            block.append("=" * 60)
            block.append("\n\n")
            self._write_block("\n".join(block))
            print(f"[DEBUG] Traffic Detected (Response): {host}{path}")
        except Exception as e:
            print(f"[WARN] response 훅 처리 중 예외: {e}")

addons = [AllTrafficLogger()]
