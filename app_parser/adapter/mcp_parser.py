#!/usr/bin/env python3
import re
from typing import Optional
from mitmproxy import http

MCP_ENDPOINT_SUBSTRS = [
    "aiserver.v1.AiService/NameTab",
]

class MCPParser:
    @staticmethod
    def is_mcp_flow(flow: http.HTTPFlow) -> bool:
        url = flow.request.pretty_url
        return any(s in url for s in MCP_ENDPOINT_SUBSTRS)

    @staticmethod
    def _safe_decode(content: bytes) -> str:
        if not content:
            return ""
        try:
            return content.decode("utf-8", errors="ignore")
        except Exception:
            return f"[DECODE_ERROR: {len(content)} bytes]"

    @staticmethod
    def extract_prompt(flow: http.HTTPFlow) -> Optional[str]:
        raw = MCPParser._safe_decode(flow.request.content)
        parts = raw.split('{"root":')
        if len(parts) < 2:
            return None
        last_json = '{"root":' + parts[-1]
        matches = re.findall(r'"text":"((?:[^"\\]|\\.)*)"', last_json)
        if not matches:
            return None
        return matches[0]