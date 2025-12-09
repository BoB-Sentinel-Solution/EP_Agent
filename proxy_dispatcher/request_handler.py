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
from llm_parser.adapter.chatgpt_file_handler import ChatGPTFileHandler
from llm_parser.adapter.claude_file_handler import ClaudeFileHandler
from llm_parser.adapter.gemini_file_handler import GeminiFileHandler

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

        # ChatGPT 파일 처리 전용 핸들러
        self.chatgpt_file_handler = ChatGPTFileHandler(
            server_client=server_client,
            cache_manager=cache_manager,
            log_manager=log_manager,
            public_ip=public_ip,
            private_ip=private_ip,
            hostname=hostname
        )

        # Claude 파일 처리 전용 핸들러
        self.claude_file_handler = ClaudeFileHandler(
            server_client=server_client,
            cache_manager=cache_manager,
            log_manager=log_manager,
            public_ip=public_ip,
            private_ip=private_ip,
            hostname=hostname
        )

        # Gemini 파일 처리 전용 핸들러
        self.gemini_file_handler = GeminiFileHandler(
            server_client=server_client,
            cache_manager=cache_manager,
            log_manager=log_manager,
            public_ip=public_ip,
            private_ip=private_ip,
            hostname=hostname
        )

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
        extracted_data = None
        interface = None
        step1_start = datetime.now()
        step1_end = datetime.now()
        step1_time = 0.0
        log_entry = {} # 로그 항목을 try 블록 전체에서 사용하기 위해 초기화
        
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

                # ===== ChatGPT 전용 파일/file_id 처리 =====
                if "chatgpt.com" in host or "oaiusercontent.com" in host:
                    # file_id 교체 등 ChatGPT 특수 요청 처리
                    if self.chatgpt_file_handler.process_chatgpt_specific_requests(flow, self.cache_manager):
                        # 처리 완료되었지만 계속 진행 (프롬프트 파싱 등을 위해)
                        pass

                    # POST: 파일 등록
                    if method == "POST" and ("/backend-api/files" in path or "/backend-anon/files" in path):
                        metadata = self.chatgpt_file_handler.extract_file_registration_request(flow)
                        if metadata:
                            info(f"[ChatGPT POST] 파일 등록 요청: {metadata.get('file_name')} ({metadata.get('file_size')} bytes)")
                            self.cache_manager.add_chatgpt_post_metadata(flow, metadata)
                            return  # 처리 완료

                    # PUT: 파일 업로드 (핸들러에 완전 위임)
                    if method == "PUT":
                        handled = self.chatgpt_file_handler.handle_file_upload(
                            flow,
                            host,
                            self.public_ip,
                            self.private_ip,
                            self.hostname
                        )
                        if handled:
                            return  # 처리 완료

                # ===== Claude 전용 파일/file_uuid 처리 =====
                if "claude.ai" in host:
                    # file_uuid 교체 등 Claude 특수 요청 처리
                    if self.claude_file_handler.process_claude_specific_requests(flow, self.cache_manager):
                        # 처리 완료되었지만 계속 진행 (프롬프트 파싱 등을 위해)
                        pass

                    # POST: 파일 업로드 (multipart) - /upload, /convert_document 모두 처리
                    if method == "POST" and ("/upload" in path or "/convert_document" in path):
                        handled = self.claude_file_handler.handle_file_upload(
                            flow,
                            host,
                            self.public_ip,
                            self.private_ip,
                            self.hostname
                        )
                        if handled:
                            return  # 처리 완료

                # ===== Gemini 전용 파일/file_path 처리 =====
                if "gemini.google.com" in host or "push.clients6.google.com" in host:
                    # file_path 교체 등 Gemini 특수 요청 처리
                    if self.gemini_file_handler.process_gemini_specific_requests(flow, self.cache_manager):
                        # 처리 완료되었지만 계속 진행 (프롬프트 파싱 등을 위해)
                        pass

                    # POST: 파일 등록 (첫 번째 POST - upload_id 없음)
                    if method == "POST" and "push.clients6.google.com" in host and path == "/upload/":
                        metadata = self.gemini_file_handler.extract_file_registration_request(flow)
                        if metadata:
                            info(f"[Gemini POST] 파일 등록 요청: {metadata.get('file_name')} ({metadata.get('file_size')} bytes)")
                            self.cache_manager.add_gemini_post_metadata(flow, metadata)
                            return  # 처리 완료

                    # POST: 파일 업로드 (두 번째 POST - resumable upload with upload_id)
                    if method == "POST" and "push.clients6.google.com" in host and "/upload" in path and "upload_id=" in path:
                        handled = self.gemini_file_handler.handle_file_upload(
                            flow,
                            host,
                            self.public_ip,
                            self.private_ip,
                            self.hostname
                        )
                        if handled:
                            return  # 처리 완료

                # ===== 다른 LLM 파일 업로드 처리 =====
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
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
                extracted_data = file_info
                
                # tool_call 처리 (로그 재기록 후 리턴)
                if extracted_data and extracted_data.get("event") == "tool_call":
                    last_user = self.log_manager.load_last_user()
                    if last_user:
                        log_entry_for_mcp = dict(last_user)
                        log_entry_for_mcp["interface"] = "mcp"
                        log_entry_for_mcp["time"] = datetime.now().isoformat()
                        log_entry_for_mcp["meta"] = {**(log_entry_for_mcp.get("meta") or {}), **(extracted_data.get("meta") or {})}
                        self.log_manager.save_log(log_entry_for_mcp)
                        info("[MCP] tool 콜 감지 → 직전 user 로그를 MCP로 재기록 완료")
                    return # tool_call 처리는 로그만 기록하고 함수 종료
                
                interface = extracted_data.get("interface", "llm") if extracted_data else "llm"

            # ===== App/MCP 트래픽 라우팅 =====
            elif self._is_app_request(host):
                info(f"[DISPATCHER] App/MCP 요청으로 라우팅: {host}")
                if not self.app_handler:
                    info(f"[DISPATCHER] ✗ App/MCP 핸들러가 초기화되지 않음!")
                    return


                active_handler = self.app_handler
                step1_start = datetime.now()
                extracted_data = self.app_handler.extract_prompt_only(flow)
                step1_end = datetime.now()
                step1_time = (step1_end - step1_start).total_seconds()
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
                
                # VSCode MCP 감지 및 업데이트 (즉시 리턴)
                if extracted_data and extracted_data.get("event") == "mcp_call":
                    last_user_log = self.log_manager.load_vscode_last_user()
                    if last_user_log:
                        self.log_manager.update_log_to_mcp(last_user_log)
                        info("[MCP] Copilot MCP 사용 감지 -> 원본 user 로그의 interface를 'mcp'로 수정 완료.")
                    return
                
                interface = extracted_data.get("interface", "app") if extracted_data else "app"

            # 3. ===== 매칭되지 않는 트래픽은 통과 =====
            else:
                info(f"[DISPATCHER] 매칭되지 않는 호스트, 통과: {host}")
                return

            # 추출된 데이터가 없으면 종료
            if not (extracted_data and extracted_data.get("prompt")):
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

            meta = (extracted_data or {}).get("meta") or {}
            if interface == "llm" and active_handler == self.llm_handler and meta.get("role") == "user":
                self.log_manager.save_last_user(log_entry)

            if interface == "llm" and active_handler == self.app_handler: # VSCode Copilot user 요청 임시 저장
                context = extracted_data.get("context", {})
                tag = context.get("tag")
                if tag in ["prompt", "userRequest", "user_query"]:
                    self.log_manager.save_vscode_last_user(log_entry)
                    info(f"[HANDLER] Copilot user 요청 임시 저장 (tag: {tag})")
            
            # 4. ===== 서버 통신 및 후처리 (GPT, LLM, App 모두 동일하게 적용) =====
            info(f"[REQUEST] {interface.upper()} 요청 감지 - 서버로 전송, 홀딩 시작...")
            
            
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


