#!/usr/bin/env python3
"""
Request Handler - 요청 트래픽 처리
"""
from datetime import datetime
from typing import Set, Optional, Dict, Any
from mitmproxy import http, ctx
import base64
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

                # ===== ChatGPT 파일 POST 요청 감지 - 캐시 저장 =====
                if "chatgpt.com" in host and method == "POST" and ("/backend-api/files" in path or "/backend-anon/files" in path):
                    adapter = self.llm_handler.get_adapter(host)
                    if adapter and hasattr(adapter, 'extract_file_registration_request'):
                        metadata = adapter.extract_file_registration_request(flow)
                        if metadata:
                            info(f"[ChatGPT POST] 파일 메타데이터 감지: {metadata.get('file_name')} | {metadata.get('file_size')} bytes")
                            self.cache_manager.add_chatgpt_post_metadata(flow, metadata)
                            info(f"[ChatGPT POST] 캐시 저장 완료, 원본 그대로 통과 → ChatGPT 서버")
                            return  # 원본 POST 그대로 전송

                # ===== ChatGPT 파일 PUT 요청 감지 - 처리 시작 =====
                if ("chatgpt.com" in host or "oaiusercontent.com" in host) and method == "PUT":
                    adapter = self.llm_handler.get_adapter(host)
                    if adapter and hasattr(adapter, 'extract_file_from_upload_request'):
                        put_file_info = adapter.extract_file_from_upload_request(flow)
                        if put_file_info and put_file_info.get("file_id"):
                            attachment = put_file_info["attachment"]
                            file_id = put_file_info["file_id"]
                            info(f"[ChatGPT PUT] 파일 업로드 감지: {file_id} | {attachment.get('format')} | {attachment.get('size')} bytes")

                            # 캐시에서 POST 메타데이터 가져오기
                            post_data = self.cache_manager.get_recent_chatgpt_post()

                            if not post_data:
                                info(f"[ChatGPT PUT] 매칭되는 POST 없음, 원본 그대로 통과")
                                return

                            info(f"[ChatGPT] POST 메타데이터 매칭 성공")
                            
                            # ===== 서버로 파일 정보 전송 → 변조 정보 받기 =====
                            metadata = post_data["metadata"]
                            file_log_entry = {
                                "time": datetime.now().isoformat(),
                                "public_ip": self.public_ip,
                                "private_ip": self.private_ip,
                                "host": host,
                                "PCName": self.hostname,
                                "prompt": f"[FILE: {metadata.get('file_name')}]",
                                "attachment": attachment,  # 원본 파일 정보 (format, size, data)
                                "interface": "llm",
                                "file_id": file_id
                            }

                            info(f"[ChatGPT] 서버로 파일 정보 전송, 홀딩 시작...")
                            file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, 0)
                            info(f"[ChatGPT] 서버 응답 받음, 홀딩 완료")

                            # 서버 응답에서 변조 정보 가져오기
                            response_attachment = file_decision.get("attachment", {})
                            file_change = response_attachment.get("file_change", False)
                            modified_file_data = response_attachment.get("data")
                            modified_file_size = response_attachment.get("size")

                            if not file_change:
                                info(f"[ChatGPT] 파일 변조 안함, 원본 그대로 통과")
                                return

                            if not modified_file_size:
                                info(f"[ChatGPT] ✗ 서버 응답에 size 없음, 원본 크기 사용")
                                modified_file_size = metadata.get("file_size")
                            else:
                                info(f"[ChatGPT] ✓ 변조된 파일 크기: {modified_file_size} bytes")

                            if not modified_file_data:
                                info(f"[ChatGPT] ⚠ 변조할 파일 데이터 없음")
                                return

                            # ===== 변조 정보로 처리 시작 =====
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
                    info(f"[FILE] 파일 업로드 감지 - 서버로 전송, 홀딩 시작: file_id={file_id}")
                    file_decision, _, _ = self.server_client.get_control_decision(file_log_entry, step1_time)
                    info(f"[FILE] 서버 응답 받음, 홀딩 완료")

                    # ===== 파일 변조 =====
                    response_attachment = file_decision.get("attachment", {})
                    file_change = response_attachment.get("file_change", False)
                    modified_file_data = response_attachment.get("data")
                    modified_file_size = None

                    if file_change and modified_file_data:
                        info(f"[FILE] 파일 변조 시작... file_id={file_id}")
                        adapter = self.llm_handler.get_adapter(host)
                        if adapter and hasattr(adapter, 'modify_file_data'):
                            success = adapter.modify_file_data(flow, modified_file_data)
                            if success:
                                info(f"[FILE] 파일 변조 완료! file_id={file_id}")
                                # 변조된 파일 크기 계산
                                import base64
                                try:
                                    modified_bytes = base64.b64decode(modified_file_data)
                                    modified_file_size = len(modified_bytes)
                                    info(f"[FILE] 변조된 파일 크기: {modified_file_size} bytes")
                                except:
                                    pass
                            else:
                                info(f"[FILE] 파일 변조 실패! file_id={file_id}")
                        else:
                            info(f"[FILE] Adapter에 modify_file_data 함수가 없습니다.")
                    else:
                        info(f"[FILE] 파일 변조 안함 (file_change={file_change})")

                    # 캐시에 파일 정보 저장 (POST에서 사용)
                    self.cache_manager.add_file(file_id, attachment, None, step1_time)
                    info(f"[FILE] 파일 처리 완료 - 릴리즈: file_id={file_id}")

                    return  # 파일 처리 완료 후 종료

                # ===== 프롬프트 요청 처리 =====
                step1_start = datetime.now()
                extracted_data = file_info  # 위에서 이미 extract_prompt_only 호출됨
                step1_end = datetime.now()
                info(f"[Step0] 프롬프트 파싱 끝난 시간: {step1_end.strftime('%H:%M:%S.%f')[:-3]}")
                step1_time = (step1_end - step1_start).total_seconds()
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
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
                info(f"[Step1] 프롬프트 파싱 시간: {step1_time:.4f}초")
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

            # ===== 캐시에서 파일 정보 가져오기 (LLM 요청만) =====
            if interface == "llm" and flow.request.content:
                try:
                    request_body = flow.request.content.decode('utf-8', errors='ignore')
                    cached_attachment = self.cache_manager.get_cached_file(host, request_body)
                    if cached_attachment:
                        attachment = cached_attachment
                        info(f"[CACHE] 파일 정보 매칭 완료: format={attachment.get('format')}")
                except Exception as e:
                    info(f"[CACHE] 오류: {e}")

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
            info("프롬프트만 서버로 전송, 홀딩 시작...")
            start_time = datetime.now()
            info(f"서버로 전송한 시간: {start_time.strftime('%H:%M:%S.%f')[:-3]}")

            prompt_to_server_time = (start_time - step1_end).total_seconds()
            info(f"프롬프트 파싱부터 서버로 전송까지 걸린 시간: {prompt_to_server_time:.4f}초")

            prompt_decision, step2_timestamp, step3_timestamp = self.server_client.get_control_decision(prompt_log_entry, step1_time)
            end_time = datetime.now()

            if step2_timestamp and step3_timestamp:
                info(f"[Step2] 서버 요청 시점: {step2_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                info(f"[Step3] 서버 응답 시점: {step3_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                network_time = (step3_timestamp - step2_timestamp).total_seconds()
                info(f"네트워크 송수신 시간: {network_time:.4f}초")

            elapsed = (end_time - start_time).total_seconds()
            info(f"홀딩 완료! 소요시간: {elapsed:.4f}초")

            # ===== 패킷 변조 및 알림 처리 =====
            modified_prompt = prompt_decision.get("modified_prompt")
            alert_message = prompt_decision.get("alert")

            # alert 값이 있는지 확인 (alert가 트리거)
            has_alert = alert_message is not None and alert_message != ""

            if has_alert:
                # alert가 있을 때만 알림창 표시
                info(f"[ALERT] 알림 메시지: {alert_message}")

                # modified_prompt 확인
                has_modified_prompt = modified_prompt is not None and modified_prompt != ""

                if has_modified_prompt:
                    info(f"[MODIFY] 원본: {log_entry['prompt'][:50]}... -> 변조: {modified_prompt[:50]}...")
                    log_entry['prompt'] = modified_prompt

                # 알림창 먼저 표시 (모달 - 사용자 확인 대기)
                try:
                    info(f"[NOTIFY] 알림창 표시 중... 사용자 확인 대기")
                    show_modification_alert(
                        prompt,
                        modified_prompt if has_modified_prompt else None,
                        alert_message,
                        host
                    )
                    info(f"[NOTIFY] 사용자 확인 완료")

                    # 사용자 확인 후 패킷 변조 수행 (modified_prompt가 있을 때만)
                    if has_modified_prompt:
                        if not active_handler:
                            info(f"[MODIFY] 오류: 'active_handler'가 설정되지 않았습니다.")
                        elif not hasattr(active_handler, 'modify_request'):
                            info(f"[MODIFY] 오류: {type(active_handler).__name__}에 'modify_request' 함수가 없습니다.")
                        else:
                            info(f"[MODIFY] {type(active_handler).__name__}를 사용하여 패킷 변조 시도...")
                            active_handler.modify_request(flow, modified_prompt, extracted_data)
                            info(f"[MODIFY] 프롬프트 변조 완료 - LLM 서버로 요청 전송")

                except Exception as e:
                    info(f"[MODIFY] 처리 실패: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                # alert가 없으면 알림 없이 그냥 통과
                info(f"[INFO] 알림 없음 - 요청 그대로 진행")

            # ===== 통합 로그 저장 =====
            log_entry["holding_time"] = elapsed
            self.log_manager.save_log(log_entry)

            info(f"{interface.upper()} 요청 처리 완료")

        except Exception as e:
            info(f"[ERROR] 요청 처리 오류: {e}")
            import traceback
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

            info(f"[ChatGPT] 원본 파일명: {metadata.get('file_name')}, 원본 크기: {metadata.get('file_size')} bytes")
            info(f"[ChatGPT] 변조 파일 크기: {modified_file_size} bytes")

            # ===== 변조 파일 정보 상세 로깅 =====
            info(f"[ChatGPT] ===== 서버에서 받은 변조 정보 =====")
            info(f"[ChatGPT] format: {modified_attachment.get('format')}")
            info(f"[ChatGPT] size: {modified_file_size}")
            info(f"[ChatGPT] file_change: {modified_attachment.get('file_change')}")
            info(f"[ChatGPT] data length: {len(modified_file_data) if modified_file_data else 0} chars (base64)")
            
            # base64 디코딩해서 실제 파일 크기 확인
            import base64
            try:
                decoded = base64.b64decode(modified_file_data)
                info(f"[ChatGPT] 실제 디코딩된 파일 크기: {len(decoded)} bytes")
                # 첫 20바이트 hex로 확인
                info(f"[ChatGPT] 파일 시작 바이트 (hex): {decoded[:20].hex()}")
            except:
                pass
            info(f"[ChatGPT] =====================================")

            # ===== 1. 새로운 POST 전송 =====
            adapter = self.llm_handler.get_adapter("chatgpt.com")
            
            if not adapter or not hasattr(adapter, 'send_new_post_request'):
                info(f"[ChatGPT] ✗ Adapter에 send_new_post_request 함수 없음")
                return

            info(f"[ChatGPT] 새 POST 전송 시작: file_size={modified_file_size}")
            success, upload_url = adapter.send_new_post_request(post_flow, modified_file_size)
            
            if not success or not upload_url:
                info(f"[ChatGPT] ✗ 새 POST 전송 실패 또는 upload_url 없음")
                return

            info(f"[ChatGPT] ✓ 새 POST 전송 성공")
            info(f"[ChatGPT] ✓ upload_url 받음: {upload_url[:100]}...")

            # ===== 2. PUT 요청 수정 (URL + 파일 데이터) =====
            # 2-1. URL 변경
            old_url = put_flow.request.url
            put_flow.request.url = upload_url
            info(f"[ChatGPT PUT] URL 변경:")
            info(f"  OLD: {old_url}")
            info(f"  NEW: {upload_url}")

            # 2-2. 파일 데이터 변조
            if hasattr(adapter, 'modify_file_data'):
                success = adapter.modify_file_data(put_flow, modified_file_data)
                if success:
                    info(f"[ChatGPT PUT] ✓ 파일 데이터 변조 완료")
                else:
                    info(f"[ChatGPT PUT] ✗ 파일 데이터 변조 실패")
                    return
            else:
                info(f"[ChatGPT PUT] ✗ Adapter에 modify_file_data 함수 없음")
                return

            # ===== 최종 확인 =====
            info(f"[ChatGPT] ===== 최종 전송 패킷 요약 =====")
            info(f"[ChatGPT] 가짜 POST로 등록한 file_id: {upload_url.split('/files/')[1].split('/')[0] if '/files/' in upload_url else 'unknown'}")
            info(f"[ChatGPT] PUT이 전송될 URL: {put_flow.request.url[:100]}...")
            info(f"[ChatGPT] PUT Body 크기: {len(put_flow.request.content)} bytes")
            info(f"[ChatGPT] =====================================")

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

            info(f"[ChatGPT] ✓ 파일 위변조 처리 완료!")

        except Exception as e:
            info(f"[ERROR] ChatGPT 파일 위변조 처리 오류: {e}")
            import traceback
            traceback.print_exc()


