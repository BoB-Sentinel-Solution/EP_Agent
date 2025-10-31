#!/usr/bin/env python3
"""
Windsurf 애플리케이션 어댑터
- server.self-serve.windsurf.com/exa.api_server_pb.ApiServerService/RecordCortexTrajectoryStep
- server.self-serve.windsurf.com/exa.api_server_pb.ApiServerService/GetChatMessage
- Protobuf 형식 (gzip 압축)
- Google protobuf 라이브러리를 사용한 wire format 파싱
- 파싱 경로: [최상위 Field #2] → field #19 → field #2
- 중복 방지: 5초 이내 동일 프롬프트 무시
"""
import re
import gzip
import datetime
import time
from typing import Optional, Dict, Any, List
from mitmproxy import http
from google.protobuf.internal import decoder, wire_format


class WindsurfAdapter:
    def __init__(self):
        print(f"[WINDSURF] WindsurfAdapter 초기화 완료")
        # 중복 방지용
        self.last_prompt = None
        self.last_prompt_time = 0

    def _is_windsurf_chat_flow(self, flow: http.HTTPFlow) -> bool:
        """Windsurf 채팅 요청인지 확인 (두 엔드포인트 모두 감시)"""
        url = flow.request.pretty_url

        windsurf_endpoints = [
            "RecordCortexTrajectoryStep",  # 감시는 하되,
            "GetChatMessage",             # 이것만 선별
            # "RecordCortexExecutionMetadata",
        ]

        if "server.self-serve.windsurf.com" not in url:
            return False

        return any(endpoint in url for endpoint in windsurf_endpoints)

    def _safe_decode(self, content: bytes) -> str:
        # ... (이 함수는 변경 없음)
        try:
            if len(content) >= 2 and content[:2] == b'\x1f\x8b':
                content = gzip.decompress(content)
        except Exception:
            pass
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return content.decode('latin-1', errors='replace')

    def _extract_field_2_string(self, data: bytes) -> Optional[str]:
        # ... (이 함수는 변경 없음)
        print(f"[WINDSURF] ...       field number 2(문자열) 검색...")
        pos = 0
        while pos < len(data):
            try:
                tag, new_pos = decoder._DecodeVarint(data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x7
                if field_number == 2 and wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                    print(f"[WINDSURF] ... ✓✓✓✓ field number 2 발견!")
                    length, new_pos = decoder._DecodeVarint(data, new_pos)
                    if new_pos + length > len(data):
                        print(f"[WINDSURF] ... ✗ 길이 초과")
                        pos = new_pos
                        continue
                    string_data = data[new_pos:new_pos + length]
                    try:
                        prompt = string_data.decode('utf-8', errors='strict')
                        print(f"[WINDSURF] ... ✓✓✓✓✓ 프롬프트 추출 성공!")
                        return prompt.strip()
                    except UnicodeDecodeError as e:
                        print(f"[WINDSURF] ... ✗ UTF-8 디코딩 실패: {e}")
                        pos = new_pos + length
                        continue
                elif wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                    length, new_pos = decoder._DecodeVarint(data, new_pos)
                    pos = new_pos + length
                elif wire_type == wire_format.WIRETYPE_VARINT:
                    _, pos = decoder._DecodeVarint(data, new_pos)
                elif wire_type == wire_format.WIRETYPE_FIXED64:
                    pos = new_pos + 8
                elif wire_type == wire_format.WIRETYPE_FIXED32:
                    pos = new_pos + 4
                else:
                    pos = new_pos
            except Exception as e:
                print(f"[WINDSURF] ... field #2 파싱 오류: {e}")
                pos += 1
        return None

    def _extract_field_19_from_field_4(self, field_4_data: bytes) -> Optional[str]:
        # ... (이 함수는 변경 없음)
        print(f"[WINDSURF] ...   field number 19 검색 시작...")
        pos = 0
        while pos < len(field_4_data):
            try:
                tag, new_pos = decoder._DecodeVarint(field_4_data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x7
                if field_number == 19 and wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                    print(f"[WINDSURF] ... ✓✓ field number 19 발견!")
                    length, new_pos = decoder._DecodeVarint(field_4_data, new_pos)
                    if new_pos + length > len(field_4_data):
                        print(f"[WINDSURF] ... ✗ 길이 초과")
                        pos = new_pos
                        continue
                    field_19_data = field_4_data[new_pos:new_pos + length]
                    print(f"[WINDSURF] ... field #19 중첩 메시지 크기: {length} bytes")
                    prompt = self._extract_field_2_string(field_19_data)
                    if prompt:
                        return prompt
                    pos = new_pos + length
                elif wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                    length, new_pos = decoder._DecodeVarint(field_4_data, new_pos)
                    pos = new_pos + length
                elif wire_type == wire_format.WIRETYPE_VARINT:
                    _, pos = decoder._DecodeVarint(field_4_data, new_pos)
                elif wire_type == wire_format.WIRETYPE_FIXED64:
                    pos = new_pos + 8
                elif wire_type == wire_format.WIRETYPE_FIXED32:
                    pos = new_pos + 4
                else:
                    pos = new_pos
            except Exception as e:
                print(f"[WINDSURF] ... field #19 파싱 오류 at pos={pos}: {e}")
                pos += 1
        return None

    def _extract_prompt_from_body(self, raw_body: bytes) -> Optional[str]:
        # ... (이 함수는 변경 없음)
        print(f"\n{'='*60}")
        print(f"[WINDSURF] _extract_prompt_from_body 시작")
        print(f"[WINDSURF] 입력 데이터 크기: {len(raw_body)} bytes")
        print(f"[WINDSURF] 첫 40 bytes (hex): {raw_body[:40].hex()}")
        print(f"{'='*60}\n")
        print(f"[WINDSURF] 1단계: 모든 최상위 LENGTH_DELIMITED 필드 탐색 시작...")
        pos = 0
        while pos < len(raw_body):
            try:
                tag, new_pos = decoder._DecodeVarint(raw_body, pos)
                field_number = tag >> 3
                wire_type = tag & 0x7
                print(f"[WINDSURF] 최상위 필드: field_number={field_number}, wire_type={wire_type}")
                if wire_type == wire_format.WIRETYPE_LENGTH_DELIMITED:
                    print(f"[WINDSURF] ✓ Field #{field_number} (LENGTH_DELIMITED) 발견, 내부 탐색 시도...")
                    length, new_pos = decoder._DecodeVarint(raw_body, new_pos)
                    if new_pos + length > len(raw_body):
                        print(f"[WINDSURF] ✗ 길이 초과, 스킵")
                        pos = new_pos
                        continue
                    nested_message_data = raw_body[new_pos:new_pos + length]
                    print(f"[WINDSURF] Field #{field_number} 중첩 메시지 크기: {length} bytes")
                    prompt = self._extract_field_19_from_field_4(nested_message_data)
                    if prompt:
                        print(f"\n{'='*60}")
                        print(f"[WINDSURF] ✓✓✓✓✓ 프롬프트 추출 성공! (Field #{field_number} 내부에서 발견)")
                        print(f"[WINDSURF] 길이: {len(prompt)} characters")
                        print(f"[WINDSURF] 전체 내용: '{prompt}'")
                        print(f"{'='*60}\n")
                        return prompt
                    print(f"[WINDSURF] ✗ Field #{field_number}에서 프롬프트를 찾지 못함. 다음 필드 탐색...")
                    pos = new_pos + length
                elif wire_type == wire_format.WIRETYPE_VARINT:
                    _, pos = decoder._DecodeVarint(raw_body, new_pos)
                elif wire_type == wire_format.WIRETYPE_FIXED64:
                    pos = new_pos + 8
                elif wire_type == wire_format.WIRETYPE_FIXED32:
                    pos = new_pos + 4
                else:
                    pos = new_pos
            except Exception as e:
                print(f"[WINDSURF] 파싱 오류: {e}")
                pos += 1
        print(f"\n{'='*60}")
        print(f"[WINDSURF] ✗✗✗ 모든 최상위 필드 탐색 완료, 프롬프트 추출 실패")
        print(f"{'='*66}\n")
        return None

    def _modify_prompt_in_protobuf(self, raw_body: bytes, original_prompt: str, new_prompt: str) -> bytes:
        """
        Protobuf body에서 프롬프트를 수정
        원본 프롬프트를 새 프롬프트로 교체하고 length 필드도 업데이트
        """
        print(f"\n[WINDSURF MODIFY] 프롬프트 위변조 시작...")
        print(f"[WINDSURF MODIFY] 원본: {original_prompt}")
        print(f"[WINDSURF MODIFY] 수정: {new_prompt}")

        try:
            original_bytes = original_prompt.encode('utf-8')
            new_bytes = new_prompt.encode('utf-8')

            # 원본 프롬프트를 바이트로 찾아서 교체
            if original_bytes in raw_body:
                print(f"[WINDSURF MODIFY] ✓ 원본 프롬프트 발견, 교체 중...")

                # 프롬프트 앞에 있는 length 필드도 수정해야 함
                # Protobuf varint로 인코딩된 length 찾기
                original_length = len(original_bytes)
                new_length = len(new_bytes)

                # 간단한 교체 (같은 위치에 여러 번 나올 수 있으므로 첫 번째만 교체)
                modified_body = raw_body.replace(original_bytes, new_bytes, 1)

                print(f"[WINDSURF MODIFY] ✓ 교체 완료 (크기 변화: {len(raw_body)} → {len(modified_body)} bytes)")
                return modified_body
            else:
                print(f"[WINDSURF MODIFY] ✗ 원본 프롬프트를 body에서 찾지 못함")
                return raw_body

        except Exception as e:
            print(f"[WINDSURF MODIFY] ✗ 위변조 실패: {e}")
            return raw_body

    # --- ⚠️ 여기가 수정됨 ⚠️ ---
    def extract_prompt(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        프롬프트 추출. GetChatMessage 요청만 선별하여 반환.
        반환: {"prompt": str, "interface": str} 또는 None
        """
        print(f"\n{'#'*80}")
        print(f"[WINDSURF] extract_prompt 호출")
        print(f"[WINDSURF] URL: {flow.request.pretty_host}{flow.request.path}")
        print(f"[WINDSURF] Method: {flow.request.method}")
        print(f"{'#'*80}\n")

        # Windsurf 채팅 요청 확인 (Record... 와 GetChat... 둘 다 감시)
        if not self._is_windsurf_chat_flow(flow):
            print(f"[WINDSURF] ✗ Windsurf 채팅 요청이 아님 (URL 매칭 실패)")
            return None

        print(f"[WINDSURF] ✓ Windsurf 채팅 요청 감지됨")

        # Body 가져오기 및 gzip 해제
        raw_body = flow.request.content
        # ... (중략) ...
        gzip_magic_number = b'\x1f\x8b'
        gzip_start_index = raw_body.find(gzip_magic_number)
        
        if gzip_start_index != -1:
            gzipped_data = raw_body[gzip_start_index:]
            try:
                raw_body = gzip.decompress(gzipped_data)
                print(f"[WINDSURF] ✓ gzip 압축 해제 성공")
                print(f"[WINDSURF] 압축 해제 후 크기: {len(raw_body)} bytes")
            except Exception as e:
                print(f"[WINDSURF] ✗ gzip 해제 실패 (원본 사용): {e}")
        else:
            print(f"[WINDSURF] gzip 데이터가 아니거나 헤더가 없어 원본 사용")
        
        # 프롬프트 추출
        prompt = self._extract_prompt_from_body(raw_body)
        prompt_text = prompt.strip() if prompt else None

        if not prompt_text:
            print(f"\n{'='*60}")
            print(f"[WINDSURF] ✗✗✗ 최종 프롬프트 추출 실패 또는 비어있음")
            print(f"{'='*60}\n")
            return None

        # --- 중복 방지 로직 ---
        current_time = time.time()
        # 같은 프롬프트가 5초 이내에 다시 오면 무시 (중복 방지)
        if self.last_prompt == prompt_text and (current_time - self.last_prompt_time) < 5:
            print(f"\n{'='*60}")
            print(f"[WINDSURF] ✗ 중복 프롬프트 감지 (5초 이내 동일 프롬프트). 무시함.")
            print(f"[WINDSURF] 미리보기: {prompt_text[:100]}...")
            print(f"{'='*60}\n")
            return None

        # 프롬프트 기록
        self.last_prompt = prompt_text
        self.last_prompt_time = current_time

        # RecordCortexTrajectoryStep에서 프롬프트 추출 성공 시 반환
        print(f"\n{'='*60}")
        print(f"[WINDSURF] ✓✓✓ 프롬프트 추출 성공! 반환.")
        print(f"[WINDSURF] 엔드포인트: {flow.request.path.split('/')[-1]}")
        print(f"[WINDSURF] 길이: {len(prompt_text)} characters")
        print(f"[WINDSURF] 미리보기: {prompt_text[:100]}...")
        print(f"{'='*60}\n")
        return {"prompt": prompt_text, "interface": "windsurf"}