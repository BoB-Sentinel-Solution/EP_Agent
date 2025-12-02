#!/usr/bin/env python3
"""
Request Handler - 요청 트래픽 처리
"""
from datetime import datetime
from typing import Set, Optional, Dict, Any
from mitmproxy import http, ctx
import base64
import json
import re
import traceback
import logging
from .server_client import ServerClient
from .cache_manager import FileCacheManager
from .log_manager import LogManager
from .response_handler import show_modification_alert

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


class RequestHandler:
    """Request 트래픽 처리 핸들러"""

    def __init__(
        self,
        llm_hosts: Set[str],
        app_hosts: Set[str],
        llm_handler,
        app_handler,
        server_client: ServerClient,
        cache_manager: FileCacheManager,
        log_manager: LogManager,
        public_ip: str,
        private_ip: str,
        hostname: str
    ):
        """
        Args:
            llm_hosts: LLM 호스트 집합
            app_hosts: App/MCP 호스트 집합
            llm_handler: LLM 핸들러 (UnifiedLLMLogger)
            app_handler: App/MCP 핸들러 (UnifiedAppLogger)
            server_client: 서버 통신 클라이언트
            cache_manager: 파일 캐시 매니저
            log_manager: 로그 매니저
            public_ip: 공인 IP
            private_ip: 사설 IP
            hostname: 호스트명
        """
        self.llm_hosts = llm_hosts
        self.app_hosts = app_hosts
        self.llm_handler = llm_handler
        self.app_handler = app_handler
        self.server_client = server_client
        self.cache_manager = cache_manager
        self.log_manager = log_manager
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.hostname = hostname

    def _is_llm_request(self, host: str) -> bool:
        """LLM 요청인지 확인"""
        return any(llm_host in host for llm_host in self.llm_hosts)

    def _is_app_request(self, host: str) -> bool:
        """App/MCP 요청인지 확인"""
        return any(app_host in host for app_host in self.app_hosts)


    def process(self, flow: http.HTTPFlow):
        """
        요청 처리 메인 로직

        Args:
            flow: mitmproxy HTTPFlow 객체
        """
        active_handler = None
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path
            extracted_data = None
            interface = None

            # 모든 요청 호스트 로깅 (디버그용)
            info(f"[DISPATCHER] 요청 감지: {host} | {method} {path[:100]}")

            # ===== LLM 트래픽 라우팅 =====
            if self._is_llm_request(host):
                info(f"[DISPATCHER] LLM 요청으로 라우팅: {host}")
                if not hasattr(self, 'llm_handler') or self.llm_handler is None:
                    info(f"[DISPATCHER] ✗ LLM 핸들러가 초기화되지 않음!")
                    return

                active_handler = self.llm_handler

                # ===== ChatGPT 전용 요청 처리 (어댑터로 위임) =====
                adapter = self.llm_handler.get_adapter(host)
                if adapter and hasattr(adapter, 'process_chatgpt_specific_requests'):
                    adapter.process_chatgpt_specific_requests(flow, self.cache_manager)

                # ===== ChatGPT 파일 POST 요청 감지 - 캐시 저장 =====
                if "chatgpt.com" in host and method == "POST" and ("/backend-api/files" in path or "/backend-anon/files" in path):
                    adapter = self.llm_handler.get_adapter(host)
                    if adapter and hasattr(adapter, 'extract_file_registration_request'):
                        metadata = adapter.extract_file_registration_request(flow)
                        if metadata:
                            info(f"[ChatGPT POST] 파일 등록 요청: {metadata.get('file_name')} ({metadata.get('file_size')} bytes)")
                            self.cache_manager.add_chatgpt_post_metadata(flow, metadata)
                            return  # 원본 POST 그대로 전송

                # ===== ChatGPT 파일 PUT 요청 감지 - 처리 시작 =====
                if ("chatgpt.com" in host or "oaiusercontent.com" in host) and method == "PUT":
                    adapter = self.llm_handler.get_adapter(host)
                    if adapter and hasattr(adapter, 'extract_file_from_upload_request'):
                        put_file_info = adapter.extract_file_from_upload_request(flow)
                        if put_file_info and put_file_info.get("file_id"):
                            attachment = put_file_info["attachment"]
                            file_id = put_file_info["file_id"]

                            try:
                                file_data = base64.b64decode(attachment.get('data', ''))
                                info(f"[ChatGPT PUT] 파일 업로드 감지: {file_id} ({len(file_data)} bytes, {attachment.get('format')})")
                            except:
                                info(f"[ChatGPT PUT] 파일 업로드 감지: {file_id}")

                            # 캐시에서 POST 메타데이터 가져오기
                            post_data = self.cache_manager.get_recent_chatgpt_post()

                            if not post_data:
                                info(f"[ChatGPT PUT] ⚠ 매칭되는 POST 없음")
                                return

                            # ===== 서버로 파일 정보 전송 → 변조 정보 받기 =====
                            metadata = post_data["metadata"]
                            attachment["size"] = metadata.get("file_size", 0)

                            file_log_entry = {
                                "time": datetime.now().isoformat(),
                                "public_ip": self.public_ip,
                                "private_ip": self.private_ip,
                                "host": host,
                                "PCName": self.hostname,
                                "prompt": f"[FILE: {metadata.get('file_name')}]",
                                "attachment": attachment,
                                "interface": "llm"
                            }

                            info(f"[ChatGPT] 서버로 파일 정보 전송, 홀딩 시작...")
                            file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, 0)
                            info(f"[ChatGPT] 서버 응답 받음")

                            # 서버 응답에서 변조 정보 가져오기
                            response_attachment = file_decision.get("attachment", {})
                            file_change = response_attachment.get("file_change", False)
                            modified_file_data = response_attachment.get("data")
                            modified_file_size = response_attachment.get("size")

                            if not file_change:
                                info(f"[ChatGPT] 파일 변조 안함")
                                return

                            if not modified_file_data:
                                info(f"[ChatGPT] ⚠ 변조할 파일 데이터 없음")
                                return

                            if not modified_file_size:
                                modified_file_size = metadata.get("file_size")

                            # ===== 파일 포맷에 따라 처리 분기 =====
                            file_format = attachment.get("format", "").lower()
                            is_image = file_format in ["png", "jpg", "jpeg", "gif", "webp", "bmp"]

                            if is_image:
                                # 이미지: PUT body만 변조 (크기 동일)
                                info(f"[ChatGPT] 이미지 파일 변조: {file_format} ({modified_file_size} bytes)")
                                adapter = self.llm_handler.get_adapter(host)
                                if adapter and hasattr(adapter, 'modify_file_data'):
                                    success = adapter.modify_file_data(flow, modified_file_data)
                                    if success:
                                        info(f"[ChatGPT] ✓ 이미지 변조 완료")
                                    else:
                                        info(f"[ChatGPT] ✗ 이미지 변조 실패")
                                else:
                                    info(f"[ChatGPT] ✗ Adapter에 modify_file_data 함수 없음")
                            else:
                                # 문서 파일: 새 POST 생성 후 처리 (크기 변경 가능)
                                info(f"[ChatGPT] 문서 파일 변조: {file_format} ({metadata.get('file_size')} → {modified_file_size} bytes)")
                                self._process_chatgpt_file_with_new_post(
                                    post_data,
                                    flow,
                                    {
                                        "format": attachment.get("format"),
                                        "size": modified_file_size,
                                        "data": modified_file_data,
                                        "file_change": True
                                    }
                                )
                                info(f"[ChatGPT] ✓ 문서 파일 위변조 완료")

                            return  # ChatGPT 파일 처리 완료 후 종료

                # ===== Claude 등 다른 LLM 파일 업로드 처리 =====
                file_info = self.llm_handler.extract_prompt_only(flow)

                if file_info and file_info.get("file_id"):
                    # 파일 업로드 감지됨 → 서버로 전송 (홀딩)
                    step1_start = datetime.now()
                    step1_end = datetime.now()
                    step1_time = (step1_end - step1_start).total_seconds()

                    file_id = file_info["file_id"]
                    attachment = file_info["attachment"]

                    # 파일 전용 로그 엔트리 생성 (프롬프트 없음)
                    file_log_entry = {
                        "time": datetime.now().isoformat(),
                        "public_ip": self.public_ip,
                        "private_ip": self.private_ip,
                        "host": host,
                        "PCName": self.hostname,
                        "prompt": "",  # 파일만 전송
                        "attachment": attachment,
                        "interface": "llm",
                        "file_id": file_id
                    }

                    # 서버로 파일 정보 전송 (홀딩 - 응답 대기)
                    info(f"[FILE] 파일 업로드 감지, 서버 전송 중: {file_id}")
                    file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, step1_time)
                    info(f"[FILE] 서버 응답 받음")

                    # ===== 파일 변조 =====
                    response_attachment = file_decision.get("attachment", {})
                    file_change = response_attachment.get("file_change", False)
                    modified_file_data = response_attachment.get("data")
                    modified_file_size = None

                    if file_change and modified_file_data:
                        info(f"[FILE] 파일 변조 시작: {file_id}")
                        adapter = self.llm_handler.get_adapter(host)
                        if adapter and hasattr(adapter, 'modify_file_data'):
                            success = adapter.modify_file_data(flow, modified_file_data)
                            if success:
                                try:
                                    modified_bytes = base64.b64decode(modified_file_data)
                                    modified_file_size = len(modified_bytes)
                                    info(f"[FILE] ✓ 파일 변조 완료: {file_id} ({modified_file_size} bytes)")
                                except:
                                    info(f"[FILE] ✓ 파일 변조 완료: {file_id}")
                            else:
                                info(f"[FILE] ✗ 파일 변조 실패: {file_id}")
                        else:
                            info(f"[FILE] ⚠ Adapter에 modify_file_data 함수 없음")
                    else:
                        info(f"[FILE] 파일 변조 안함")

                    return  # 파일 처리 완료 후 종료

                # ===== 프롬프트 요청 처리 =====
                step1_start = datetime.now()
                extracted_data = file_info  # 위에서 이미 extract_prompt_only 호출됨
                step1_end = datetime.now()
                step1_time = (step1_end - step1_start).total_seconds()
                interface = "llm"

            # ===== App/MCP 트래픽 라우팅 =====
            elif self._is_app_request(host):
                info(f"[DISPATCHER] App/MCP 요청으로 라우팅: {host}")
                if not hasattr(self, 'app_handler') or self.app_handler is None:
                    info(f"[DISPATCHER] ✗ App/MCP 핸들러가 초기화되지 않음!")
                    return

                active_handler = self.app_handler

                step1_start = datetime.now()
                extracted_data = self.app_handler.extract_prompt_only(flow)
                step1_end = datetime.now()
                step1_time = (step1_end - step1_start).total_seconds()
                if extracted_data:
                    interface = extracted_data.get("interface", "app")
                else:
                    return  # 프롬프트 추출 실패

            # 매칭되지 않는 트래픽은 통과
            else:
                info(f"[DISPATCHER] 매칭되지 않는 호스트, 통과: {host}")
                return

            # 추출된 데이터가 없으면 종료
            if not extracted_data or not extracted_data.get("prompt"):
                return

            prompt = extracted_data["prompt"]
            attachment = extracted_data.get("attachment", {"format": None, "data": None})

            # 파일 첨부 정보 로깅
            if attachment and attachment.get("format"):
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt} [파일: {attachment.get('format')}]")
            else:
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt}")

            # ===== 프롬프트 전용 로그 항목 생성 =====
            # 프롬프트만 서버로 전송 (파일 정보는 제외)
            prompt_log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": host,
                "PCName": self.hostname,
                "prompt": prompt,
                "attachment": {"format": None, "data": None},  # 파일 없음
                "interface": interface
            }

            # 로컬 로그용 (파일 포함)
            log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": host,
                "PCName": self.hostname,
                "prompt": prompt,
                "attachment": attachment,  # 파일 포함
                "interface": interface
            }

            # ===== 서버로 전송 (홀딩) =====
            start_time = datetime.now()
            prompt_decision, step2_timestamp, step3_timestamp = self.server_client.get_control_decision(prompt_log_entry, step1_time)
            end_time = datetime.now()
            elapsed = (end_time - start_time).total_seconds()
            info(f"[홀딩] 서버 응답 완료 ({elapsed:.3f}초)")

            # ===== 패킷 변조 및 알림 처리 =====
            modified_prompt = prompt_decision.get("modified_prompt")
            alert_message = prompt_decision.get("alert")

            has_alert = alert_message is not None and alert_message != ""

            if has_alert:
                has_modified_prompt = modified_prompt is not None and modified_prompt != ""

                if has_modified_prompt:
                    info(f"[MODIFY] 프롬프트 변조 감지")
                    log_entry['prompt'] = modified_prompt

                try:
                    show_modification_alert(
                        prompt,
                        modified_prompt if has_modified_prompt else None,
                        alert_message,
                        host
                    )

                    # 사용자 확인 후 패킷 변조 수행
                    if has_modified_prompt:
                        if active_handler and hasattr(active_handler, 'modify_request'):
                            active_handler.modify_request(flow, modified_prompt, extracted_data)
                            info(f"[MODIFY] ✓ 프롬프트 변조 완료")
                        else:
                            info(f"[MODIFY] ⚠ 핸들러 또는 modify_request 함수 없음")

                except Exception as e:
                    info(f"[MODIFY] ✗ 처리 실패: {e}")
                    traceback.print_exc()

            # ===== 통합 로그 저장 =====
            log_entry["holding_time"] = elapsed
            self.log_manager.save_log(log_entry)

        except Exception as e:
            info(f"[ERROR] 요청 처리 오류: {e}")
            traceback.print_exc()

    def _process_chatgpt_file_with_new_post(self, post_data, put_flow, modified_attachment):
        """ChatGPT 파일 위변조 - 새로운 POST 전송 방식

        Args:
            post_data: {"flow": flow, "metadata": dict}
            put_flow: PUT 요청의 HTTPFlow 객체
            modified_attachment: 서버에서 받은 변조된 파일 정보 {"size": int, "data": base64, "format": str}
        """
        try:
            post_flow = post_data["flow"]
            metadata = post_data["metadata"]
            modified_file_size = modified_attachment.get("size")
            modified_file_data = modified_attachment.get("data")

            info(f"[ChatGPT] 파일 위변조: {metadata.get('file_name')} ({metadata.get('file_size')} → {modified_file_size} bytes)")

            # ===== 1. 새로운 POST 전송 =====
            adapter = self.llm_handler.get_adapter("chatgpt.com")

            if not adapter or not hasattr(adapter, 'send_new_post_request'):
                info(f"[ChatGPT] ✗ Adapter에 send_new_post_request 함수 없음")
                return

            success, upload_url = adapter.send_new_post_request(post_flow, modified_file_size)

            if not success or not upload_url:
                info(f"[ChatGPT] ✗ 새 POST 전송 실패")
                return

            info(f"[ChatGPT] ✓ 새 POST 전송 성공")

            # ===== file_id 매핑 저장 =====
            new_file_id = upload_url.split('/files/')[1].split('/')[0] if '/files/' in upload_url else None

            if new_file_id:
                original_file_id = None
                for temp_id, data in list(self.cache_manager.file_cache.items()):
                    if temp_id.startswith("original_file_id_"):
                        original_file_id = data.get("file_id")
                        del self.cache_manager.file_cache[temp_id]
                        break

                if original_file_id:
                    original_file_id_with_prefix = f"file_{original_file_id.replace('-', '')}"
                    original_size = metadata.get('file_size') if metadata else None
                    self.cache_manager.save_file_id_mapping(
                        original_file_id_with_prefix,
                        new_file_id,
                        original_size=original_size,
                        new_size=modified_file_size
                    )
                    info(f"[ChatGPT] ✓ file_id 매핑: {original_file_id_with_prefix} → {new_file_id}")
                else:
                    info(f"[ChatGPT] ⚠ 원본 file_id 없음")
            else:
                info(f"[ChatGPT] ⚠ 새 file_id 추출 실패")

            # ===== 2. PUT 요청 수정 (URL + 파일 데이터) =====
            put_flow.request.url = upload_url

            # 파일 데이터 변조
            if hasattr(adapter, 'modify_file_data'):
                success = adapter.modify_file_data(put_flow, modified_file_data)
                if not success:
                    info(f"[ChatGPT PUT] ✗ 파일 데이터 변조 실패")
                    return
            else:
                info(f"[ChatGPT PUT] ✗ Adapter에 modify_file_data 함수 없음")
                return

            # 로그 저장
            log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": "chatgpt.com",
                "PCName": self.hostname,
                "prompt": f"[FILE: {metadata.get('file_name')}]",
                "attachment": modified_attachment,
                "interface": "llm",
                "holding_time": 0
            }
            self.log_manager.save_log(log_entry)

        except Exception as e:
            info(f"[ERROR] ChatGPT 파일 위변조 오류: {e}")
            traceback.print_exc()


