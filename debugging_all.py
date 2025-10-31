#!/usr/bin/env python3
"""
트래픽 로거 - 모든 HTTP 트래픽을 사람이 읽기 쉬운 로그로 저장
Protobuf 트래픽은 Google protobuf 라이브러리로 파싱하여 출력

사용:
  mitmdump -s this_script.py --set http2=true

로그 파일:
  ~/.llm_proxy/debugging_all.json
"""

import json
import gzip
import re
from pathlib import Path
from mitmproxy import http
from datetime import datetime
from typing import List
from google.protobuf.internal import decoder, wire_format

DEBUG_LOG_FILE = Path.home() / ".llm_proxy" / "debugging_all.json"
DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

class AllTrafficLogger:
    """모든 HTTP 트래픽 디버깅 로거 (Protobuf 파싱 지원)"""

    def __init__(self):
        # Protobuf를 사용하는 호스트 패턴
        self.PROTOBUF_HOSTS = [
            "server.self-serve.windsurf.com",
            "cursor.sh",
        ]

    def _is_protobuf_request(self, host: str) -> bool:
        """Protobuf 요청인지 확인"""
        return any(pb_host in host for pb_host in self.PROTOBUF_HOSTS)

    def _parse_protobuf_to_text(self, content: bytes) -> str:
        """
        Protobuf 바이너리를 읽기 쉬운 텍스트로 변환
        모든 필드를 파싱하여 구조화된 텍스트로 출력
        """
        result = []
        result.append("=" * 60)
        result.append("PROTOBUF PARSED CONTENT")
        result.append("=" * 60)

        def parse_message(data: bytes, depth: int = 0) -> List[str]:
            lines = []
            indent = "  " * depth
            pos = 0
            field_num = 0

            while pos < len(data):
                try:
                    # Tag 읽기
                    tag, new_pos = decoder._DecodeVarint(data, pos)
                    field_number = tag >> 3
                    wire_type = tag & 0x7
                    field_num += 1

                    wire_type_name = {
                        0: "VARINT", 1: "FIXED64",
                        2: "LENGTH_DELIMITED", 5: "FIXED32"
                    }.get(wire_type, f"UNKNOWN({wire_type})")

                    lines.append(f"{indent}[Field {field_num}] #{field_number} ({wire_type_name})")

                    # LENGTH_DELIMITED (문자열, bytes, 서브메시지)
                    if wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                        length, new_pos = decoder._DecodeVarint(data, new_pos)

                        if new_pos + length > len(data):
                            lines.append(f"{indent}  ERROR: Invalid length {length}")
                            pos = new_pos
                            continue

                        field_data = data[new_pos:new_pos + length]

                        # UTF-8 문자열 시도
                        try:
                            decoded = field_data.decode('utf-8', errors='strict')
                            # 출력 가능한 문자열인지 확인
                            if re.search(r'[가-힣a-zA-Z0-9]', decoded):
                                lines.append(f"{indent}  → STRING: \"{decoded}\"")
                            else:
                                lines.append(f"{indent}  → STRING (non-printable): {len(decoded)} chars")
                        except UnicodeDecodeError:
                            # 바이너리 또는 중첩 메시지
                            if length > 10:
                                # 중첩 메시지 시도
                                lines.append(f"{indent}  → NESTED MESSAGE ({length} bytes):")
                                nested = parse_message(field_data, depth + 1)
                                if nested:
                                    lines.extend(nested)
                                else:
                                    lines.append(f"{indent}    (binary data: {field_data[:20].hex()}...)")
                            else:
                                lines.append(f"{indent}  → BYTES: {field_data.hex()}")

                        pos = new_pos + length

                    # VARINT
                    elif wire_type == wire_format.WIRETYPE_VARINT:
                        value, pos = decoder._DecodeVarint(data, new_pos)
                        lines.append(f"{indent}  → VALUE: {value}")

                    # FIXED64
                    elif wire_type == wire_format.WIRETYPE_FIXED64:
                        if new_pos + 8 <= len(data):
                            value = int.from_bytes(data[new_pos:new_pos+8], 'little')
                            lines.append(f"{indent}  → FIXED64: {value}")
                        pos = new_pos + 8

                    # FIXED32
                    elif wire_type == wire_format.WIRETYPE_FIXED32:
                        if new_pos + 4 <= len(data):
                            value = int.from_bytes(data[new_pos:new_pos+4], 'little')
                            lines.append(f"{indent}  → FIXED32: {value}")
                        pos = new_pos + 4

                    else:
                        lines.append(f"{indent}  → (skipped)")
                        pos = new_pos

                except Exception as e:
                    lines.append(f"{indent}ERROR at pos {pos}: {e}")
                    pos += 1

            return lines

        try:
            parsed = parse_message(content)
            result.extend(parsed)
        except Exception as e:
            result.append(f"PARSING ERROR: {e}")

        result.append("=" * 60)
        return "\n".join(result)

    def safe_decode_content(self, content: bytes, host: str = "") -> str:
        """바이트 컨텐츠를 안전하게 디코딩.
        gzip 압축된 경우 압축 해제 후, Protobuf인 경우 파싱하여 출력
        """
        if not content:
            return "(empty)"

        # gzip 압축 여부 체크 (magic number: 1f 8b)
        is_gzip = len(content) >= 2 and content[:2] == b'\x1f\x8b'
        original_size = len(content)

        if is_gzip:
            # gzip 압축 해제
            try:
                content = gzip.decompress(content)
                decompressed_size = len(content)
                gzip_info = f"\n[GZIP DECOMPRESSED: {original_size} bytes → {decompressed_size} bytes]\n"
            except Exception as e:
                return f"[GZIP_DECODE_ERROR: {str(e)}]"
        else:
            gzip_info = ""

        # Protobuf 요청인 경우 파싱
        if self._is_protobuf_request(host):
            protobuf_parsed = self._parse_protobuf_to_text(content)

            # 원본 hex도 함께 표시 (처음 100 bytes)
            hex_preview = f"\n[RAW HEX (first 100 bytes)]: {content[:100].hex()}\n"

            return gzip_info + hex_preview + protobuf_parsed

        # 일반 텍스트 디코딩
        try:
            decoded = content.decode('utf-8', errors='replace')
            return gzip_info + decoded
        except Exception:
            # 최후의 수단: latin-1
            return gzip_info + content.decode('latin-1', errors='replace')

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
        """요청 시점에 모든 요청 로깅 (Protobuf 파싱 지원)"""
        try:
            host = flow.request.pretty_host if flow.request else "unknown"
            path = flow.request.path if flow.request else ""
            method = flow.request.method if flow.request else "UNKNOWN"
            headers = dict(flow.request.headers) if flow.request and flow.request.headers else {}
            raw = flow.request.raw_content if getattr(flow.request, "raw_content", None) is not None else flow.request.content
            decoded = self.safe_decode_content(raw, host)

            ts = datetime.now().isoformat()
            header_block = self._format_headers(headers)

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
        """응답 완료 시 모든 요청/응답 로깅 (Protobuf 파싱 지원)"""
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

            decoded_req = self.safe_decode_content(raw_req, host)
            decoded_res = self.safe_decode_content(raw_res, host)

            ts = datetime.now().isoformat()

            # format request part (short)
            req_body_text = decoded_req if decoded_req is not None else ""

            # format response body
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
