#!/usr/bin/env python3
"""
Request Handler - 요청 트래픽 처리
"""
from datetime import datetime
from typing import Set, Optional, Dict, Any
from mitmproxy import http, ctx

# 변경: 절대임포트 우선, 실패 시 상대임포트 폴백
try:
    from proxy_dispatcher.server_client import ServerClient
    from proxy_dispatcher.log_manager import LogManager
    from proxy_dispatcher.cache_manager import FileCacheManager
    from proxy_dispatcher.response_handler import show_modification_alert
except Exception:
    from .server_client import ServerClient
    from .log_manager import LogManager
    from .cache_manager import FileCacheManager
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

                # 파일 업로드 요청 처리
                file_info = self.llm_handler.extract_prompt_only(flow)

                if file_info and file_info.get("file_id"):
                    # 파일 업로드 감지됨 → 캐시에 저장
                    step1_start = datetime.now()
                    step1_end = datetime.now()
                    step1_time = (step1_end - step1_start).total_seconds()

                    file_id = file_info["file_id"]
                    attachment = file_info["attachment"]

                    # 캐시에 파일 정보 저장
                    self.cache_manager.add_file(file_id, attachment, step1_time)
                    return  # POST 요청을 기다림

                # 프롬프트 요청 처리
                step1_start = datetime.now()
                extracted_data = file_info
                step1_end = datetime.now()
                info(f"[Step0] 프롬프트 파싱 끝난 시간: {step1_end.strftime('%H:%M:%S.%f')[:-3]}")
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

            # ===== 캐시에서 파일 정보 가져오기 (LLM 요청만) =====
            if interface == "llm" and flow.request.content:
                try:
                    request_body = flow.request.content.decode('utf-8', errors='ignore')
                    cached_attachment = self.cache_manager.get_cached_file(host, request_body)
                    if cached_attachment:
                        attachment = cached_attachment
                except Exception as e:
                    info(f"[CACHE] 오류: {e}")

            # 파일 첨부 정보 로깅
            if attachment and attachment.get("format"):
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt} [파일: {attachment.get('format')}]")
            else:
                info(f"[LOG] {interface.upper()} | {host} - {prompt[:80] if len(prompt) > 80 else prompt}")

            # ===== 통합 로그 항목 생성 =====
            log_entry = {
                "time": datetime.now().isoformat(),
                "public_ip": self.public_ip,
                "private_ip": self.private_ip,
                "host": host,
                "PCName": self.hostname,
                "prompt": prompt,
                "attachment": attachment,
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
            info("서버로 전송, 홀딩 시작...")
            start_time = datetime.now()
            info(f"서버로 전송한 시간: {start_time.strftime('%H:%M:%S.%f')[:-3]}")

            prompt_to_server_time = (start_time - step1_end).total_seconds()
            info(f"프롬프트 파싱부터 서버로 전송까지 걸린 시간: {prompt_to_server_time:.4f}초")

            decision, step2_timestamp, step3_timestamp = self.server_client.get_control_decision(log_entry, step1_time)
            end_time = datetime.now()

            if step2_timestamp and step3_timestamp:
                info(f"[Step2] 서버 요청 시점: {step2_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                info(f"[Step3] 서버 응답 시점: {step3_timestamp.strftime('%H:%M:%S.%f')[:-3]}")
                network_time = (step3_timestamp - step2_timestamp).total_seconds()
                info(f"네트워크 송수신 시간: {network_time:.4f}초")

            elapsed = (end_time - start_time).total_seconds()
            info(f"홀딩 완료! 소요시간: {elapsed:.4f}초")

            # ===== 패킷 변조 및 알림 처리 =====
            modified_prompt = decision.get("modified_prompt")
            alert_message = decision.get("alert")

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
                # 사용자가 [확인]을 누를 때까지 여기서 홀딩됨
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

                            # 통일된 인터페이스: LLM/App 모두 동일한 시그니처
                            # modify_request(flow, modified_prompt, extracted_data)
                            active_handler.modify_request(flow, modified_prompt, extracted_data)

                            info(f"[MODIFY] 패킷 변조 완료 - LLM 서버로 요청 전송")

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
