#!/usr/bin/env python3
"""
Response Handler - 응답 트래픽 처리 및 알림 모듈
"""
import tkinter as tk
from tkinter import messagebox
from typing import Set, Optional, Callable, Dict, Any
from mitmproxy import http, ctx
from datetime import datetime
import json
import traceback

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


def show_modification_alert(original_prompt: str, modified_prompt: Optional[str], alert: Optional[str], host: str):
    """
    변조/알림창 표시 (모달 - 블로킹)
    사용자가 확인 버튼을 누를 때까지 대기

    Args:
        original_prompt: 원본 프롬프트
        modified_prompt: 변조된 프롬프트 (None 가능)
        alert: 알림 메시지 (None 가능)
        host: 호스트명
    """
    try:
        info(f"[NOTIFY] 알림창 표시 시작 - {host}")

        # 독립적인 알림창 생성 (Toplevel이 아닌 새 Tk 인스턴스 사용)
        dialog = tk.Tk()

        # 제목 동적 설정
        if modified_prompt and alert:
            title = "보안 알림 - 프롬프트 변조 및 경고"
        elif modified_prompt:
            title = "프롬프트 변조 알림"
        else:
            title = "보안 알림"

        dialog.title(title)

        # 높이 동적 조정 (alert가 있으면 더 크게)
        height = 450 if not alert else 550
        dialog.geometry(f"500x{height}")
        dialog.resizable(False, False)
        dialog.attributes('-topmost', True)

        # 배경색 설정
        dialog.configure(bg='#ffffff')

        # 프롬프트 길이 제한
        max_length = 200

        # modified_prompt 처리
        if modified_prompt:
            modified_display = modified_prompt[:max_length]
            if len(modified_prompt) > max_length:
                modified_display += "..."
        else:
            modified_display = None

        # alert 처리
        if alert:
            alert_display = alert[:max_length]
            if len(alert) > max_length:
                alert_display += "..."
        else:
            alert_display = None

        # 상단 헤더 프레임
        header_frame = tk.Frame(dialog, bg='#667eea', height=70)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # 경고 아이콘 및 제목
        icon_label = tk.Label(
            header_frame,
            text="🔒",
            font=('Segoe UI', 24),
            bg='#667eea',
            fg='#ffffff'
        )
        icon_label.pack(pady=(10, 0))
        
        # 헤더 텍스트 동적 설정
        if modified_prompt and alert:
            header_text = "보안 경고가 탐지되었습니다"
        elif modified_prompt:
            header_text = "프롬프트가 변조되어 전송됩니다"
        else:
            header_text = "보안 알림이 발생했습니다"

        title_label = tk.Label(
            header_frame,
            text=header_text,
            font=('Segoe UI', 11, 'bold'),
            bg='#667eea',
            fg='#ffffff'
        )
        title_label.pack(pady=(3, 10))
        
        # 메인 컨텐츠 프레임
        content_frame = tk.Frame(dialog, bg='#ffffff')
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # 호스트 정보
        host_container = tk.Frame(content_frame, bg='#ffffff')
        host_container.pack(fill='x', pady=(0, 15))
        
        host_icon = tk.Label(
            host_container,
            text="🌐",
            font=('Segoe UI', 10),
            bg='#ffffff',
            fg='#667eea'
        )
        host_icon.pack(side='left', padx=(0, 6))
        
        host_label = tk.Label(
            host_container,
            text=f"호스트: {host}",
            font=('Segoe UI', 9),
            bg='#ffffff',
            fg='#495057',
            anchor='w'
        )
        host_label.pack(side='left', fill='x', expand=True)
        
        # 구분선
        separator1 = tk.Frame(content_frame, bg='#e9ecef', height=1)
        separator1.pack(fill='x', pady=(0, 15))

        # 알림 메시지 섹션 (alert가 있을 때만)
        if alert_display:
            alert_label = tk.Label(
                content_frame,
                text="⚠️ 보안 알림",
                font=('Segoe UI', 10, 'bold'),
                bg='#ffffff',
                fg='#dc2626',
                anchor='w'
            )
            alert_label.pack(fill='x', pady=(0, 6))

            alert_frame = tk.Frame(content_frame, bg='#fef2f2', relief='flat', bd=1, highlightbackground='#ef4444', highlightthickness=2)
            alert_frame.pack(fill='x', pady=(0, 15))

            alert_text = tk.Text(
                alert_frame,
                height=3,
                wrap='word',
                font=('Segoe UI', 9),
                bg='#fef2f2',
                fg='#7f1d1d',
                relief='flat',
                padx=10,
                pady=10,
                state='normal',
                borderwidth=0
            )
            alert_text.pack(fill='x')
            alert_text.insert('1.0', alert_display)
            alert_text.configure(state='disabled')

        # 변조된 프롬프트 섹션 (modified_prompt가 있을 때만)
        if modified_display:
            modified_label = tk.Label(
                content_frame,
                text="📝 프롬프트 변경",
                font=('Segoe UI', 10, 'bold'),
                bg='#ffffff',
                fg='#d97706',
                anchor='w'
            )
            modified_label.pack(fill='x', pady=(0, 6))

            modified_frame = tk.Frame(content_frame, bg='#fffbeb', relief='flat', bd=1, highlightbackground='#fbbf24', highlightthickness=2)
            modified_frame.pack(fill='x', pady=(0, 20))

            modified_text = tk.Text(
                modified_frame,
                height=4,
                wrap='word',
                font=('Segoe UI', 9),
                bg='#fffbeb',
                fg='#92400e',
                relief='flat',
                padx=10,
                pady=10,
                state='normal',
                borderwidth=0
            )
            modified_text.pack(fill='x')
            modified_text.insert('1.0', modified_display)
            modified_text.configure(state='disabled')
        
        # 안내 메시지
        info_frame = tk.Frame(content_frame, bg='#eef2ff', relief='flat', bd=0)
        info_frame.pack(fill='x', pady=(0, 20))

        # 안내 메시지 동적 설정
        if modified_prompt:
            info_text = "💡 [확인]을 누르면 변조된 프롬프트가 LLM 서버로 전송됩니다."
        else:
            info_text = "💡 [확인]을 누르면 요청이 계속 진행됩니다."

        info_label = tk.Label(
            info_frame,
            text=info_text,
            font=('Segoe UI', 8),
            bg='#eef2ff',
            fg='#4c51bf',
            padx=10,
            pady=8,
            anchor='w'
        )
        info_label.pack(fill='x')
        
        # 하단 버튼 프레임
        button_frame = tk.Frame(dialog, bg='#f8f9fa', height=65)
        button_frame.pack(fill='x', padx=0, pady=0)
        button_frame.pack_propagate(False)
        
        def on_confirm():
            info(f"[NOTIFY] 사용자 확인 완료 - 요청 계속 진행")
            dialog.destroy()
        
        def on_enter(e):
            confirm_button.config(bg='#5a67d8')
        
        def on_leave(e):
            confirm_button.config(bg='#667eea')
        
        # 확인 버튼
        button_container = tk.Frame(button_frame, bg='#f8f9fa')
        button_container.pack(expand=True)
        
        confirm_button = tk.Button(
            button_container,
            text="✓  확인하고 전송하기",
            font=('Segoe UI', 10, 'bold'),
            bg='#667eea',
            fg='#ffffff',
            activebackground='#5a67d8',
            activeforeground='#ffffff',
            relief='flat',
            bd=0,
            padx=40,
            pady=10,
            cursor='hand2',
            command=on_confirm
        )
        confirm_button.pack()
        
        # 호버 효과
        confirm_button.bind('<Enter>', on_enter)
        confirm_button.bind('<Leave>', on_leave)
        
        # 창 중앙 배치
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        # 모달로 설정 (블로킹)
        dialog.grab_set()
        dialog.focus_force()
        dialog.wait_window()

    except Exception as e:
        info(f"[ERROR] 알림창 표시 실패: {e}")
        import traceback
        traceback.print_exc()


class ResponseHandler:
    """Response 트래픽 처리 및 알림 핸들러"""

    def __init__(
        self,
        llm_hosts: Set[str],
        app_hosts: Set[str],
        cache_manager: Any,
        notification_callback: Optional[Callable] = None
    ):
        """
        Args:
            llm_hosts: LLM 호스트 집합
            app_hosts: App/MCP 호스트 집합
            cache_manager: 캐시 매니저 (file_id 매핑 저장용)
            notification_callback: 알림 콜백 함수
        """
        self.llm_hosts = llm_hosts
        self.app_hosts = app_hosts
        self.cache_manager = cache_manager
        self.notification_callback = notification_callback
        info("[INIT] Response Handler 초기화")


    def process(self, flow: http.HTTPFlow):
        """응답 처리 - POST/PUT 결과 확인 (현재 비활성화)"""
        #pass
        try:
            host = flow.request.pretty_host
            method = flow.request.method
            path = flow.request.path

            # ChatGPT POST 응답 로깅
            if "chatgpt.com" in host and method == "POST" and ("/backend-api/files" in path or "/backend-anon/files" in path):
                info(f"[DEBUG POST RESPONSE] ========== POST 응답 시작 ==========")
                info(f"[DEBUG POST RESPONSE] URL: {flow.request.url}")
                info(f"[DEBUG POST RESPONSE] Status Code: {flow.response.status_code}")
                info(f"[DEBUG POST RESPONSE] Response Headers:")
                for key, value in flow.response.headers.items():
                    info(f"  {key}: {value}")

                if flow.response.content:
                    try:
                        body = flow.response.content.decode('utf-8', errors='ignore')

                        # SSE (Server-Sent Events) 포맷인 경우 줄별로 출력
                        if 'event-stream' in flow.response.headers.get('content-type', ''):
                            info(f"[DEBUG POST RESPONSE] Response Body (SSE 포맷):")
                            lines = body.split('\n')
                            for i, line in enumerate(lines):
                                if line.strip():  # 빈 줄 제외
                                    info(f"  [{i+1}] {line}")
                        else:
                            # 일반 JSON인 경우
                            info(f"[DEBUG POST RESPONSE] Response Body: {body}")

                        # upload_url 추출 및 로깅
                        try:
                            data = json.loads(body)
                            upload_url = data.get('upload_url')
                            if upload_url:
                                info(f"[DEBUG POST RESPONSE] ✓ upload_url 추출: {upload_url[:100]}...")
                                file_id = upload_url.split('/files/')[1].split('/')[0] if '/files/' in upload_url else 'unknown'
                                info(f"[DEBUG POST RESPONSE] ✓ file_id from upload_url: {file_id}")
                        except Exception as e:
                            info(f"[DEBUG POST RESPONSE] JSON 파싱 실패: {e}")
                    except Exception as e:
                        info(f"[DEBUG POST RESPONSE] Response Body 처리 실패: {e}")
                        info(f"[DEBUG POST RESPONSE] Response Body: (binary, {len(flow.response.content)} bytes)")

                if flow.response.status_code in [200, 201]:
                    info(f"[DEBUG POST RESPONSE] ✓ POST 성공!")
                else:
                    info(f"[DEBUG POST RESPONSE] ✗ POST 실패! Status={flow.response.status_code}")

                info(f"[DEBUG POST RESPONSE] ========== POST 응답 끝 ==========")

            # ChatGPT PUT 응답 로깅
            if ("oaiusercontent.com" in host or "chatgpt.com" in host) and method == "PUT":
                info(f"[DEBUG PUT RESPONSE] ========== PUT 응답 시작 ==========")
                info(f"[DEBUG PUT RESPONSE] URL: {flow.request.url[:100]}...")
                info(f"[DEBUG PUT RESPONSE] Status Code: {flow.response.status_code}")
                info(f"[DEBUG PUT RESPONSE] Response Headers:")
                for key, value in flow.response.headers.items():
                    info(f"  {key}: {value}")

                if flow.response.content:
                    try:
                        body = flow.response.content.decode('utf-8', errors='ignore')
                        info(f"[DEBUG PUT RESPONSE] Response Body: {body}")
                    except:
                        info(f"[DEBUG PUT RESPONSE] Response Body: (binary, {len(flow.response.content)} bytes)")

                if flow.response.status_code in [200, 201, 204]:
                    info(f"[DEBUG PUT RESPONSE] ✓ 업로드 성공!")
                else:
                    info(f"[DEBUG PUT RESPONSE] ✗ 업로드 실패! Status={flow.response.status_code}")

                info(f"[DEBUG PUT RESPONSE] ========== PUT 응답 끝 ==========")

            # Claude POST /upload 또는 /convert_document 응답 처리
            if "claude.ai" in host and method == "POST" and ("/upload" in path or "/convert_document" in path):
                info(f"[DEBUG Claude POST RESPONSE] ========== Claude POST 응답 시작 ==========")
                info(f"[DEBUG Claude POST RESPONSE] URL: {flow.request.url}")
                info(f"[DEBUG Claude POST RESPONSE] Status Code: {flow.response.status_code}")
                info(f"[DEBUG Claude POST RESPONSE] Response Headers:")
                for key, value in flow.response.headers.items():
                    info(f"  {key}: {value}")

                if flow.response.content:
                    try:
                        body = flow.response.content.decode('utf-8', errors='ignore')
                        info(f"[DEBUG Claude POST RESPONSE] Response Body: {body[:500]}")

                        # file_uuid 추출 및 로깅
                        try:
                            data = json.loads(body)
                            file_uuid = data.get('file_uuid')
                            file_name = data.get('file_name')
                            size_bytes = data.get('size_bytes')

                            if file_uuid:
                                info(f"[DEBUG Claude POST RESPONSE] ✓ file_uuid 추출: {file_uuid}")
                                info(f"[DEBUG Claude POST RESPONSE] ✓ file_name: {file_name}")
                                info(f"[DEBUG Claude POST RESPONSE] ✓ size_bytes: {size_bytes}")

                                # 캐시 매니저에 uuid 매핑 저장 (필요시)
                                # self.cache_manager.save_claude_file_uuid(file_uuid, file_name)
                        except Exception as e:
                            info(f"[DEBUG Claude POST RESPONSE] JSON 파싱 실패: {e}")
                    except Exception as e:
                        info(f"[DEBUG Claude POST RESPONSE] Response Body 처리 실패: {e}")

                if flow.response.status_code in [200, 201]:
                    info(f"[DEBUG Claude POST RESPONSE] ✓ 업로드 성공!")
                else:
                    info(f"[DEBUG Claude POST RESPONSE] ✗ 업로드 실패! Status={flow.response.status_code}")

                info(f"[DEBUG Claude POST RESPONSE] ========== Claude POST 응답 끝 ==========")

            # Gemini POST /upload 응답 처리
            if "push.clients6.google.com" in host and method == "POST" and "/upload" in path and "upload_id=" in path:
                info(f"[DEBUG Gemini POST RESPONSE] ========== Gemini POST 응답 시작 ==========")
                info(f"[DEBUG Gemini POST RESPONSE] URL: {flow.request.url[:100]}...")
                info(f"[DEBUG Gemini POST RESPONSE] Status Code: {flow.response.status_code}")
                info(f"[DEBUG Gemini POST RESPONSE] Response Headers:")
                for key, value in flow.response.headers.items():
                    info(f"  {key}: {value}")

                if flow.response.content:
                    try:
                        # Gemini 응답은 file_path 텍스트만 포함
                        file_path = flow.response.content.decode('utf-8', errors='ignore').strip()
                        info(f"[DEBUG Gemini POST RESPONSE] Response Body (file_path): {file_path[:100]}...")

                        if file_path.startswith('/contrib_service/'):
                            info(f"[DEBUG Gemini POST RESPONSE] ✓ file_path 추출: {file_path[:50]}...")
                        else:
                            info(f"[DEBUG Gemini POST RESPONSE] ⚠ 예상치 못한 응답 형식")
                    except Exception as e:
                        info(f"[DEBUG Gemini POST RESPONSE] Response Body 처리 실패: {e}")

                if flow.response.status_code in [200, 201]:
                    info(f"[DEBUG Gemini POST RESPONSE] ✓ 업로드 성공!")
                else:
                    info(f"[DEBUG Gemini POST RESPONSE] ✗ 업로드 실패! Status={flow.response.status_code}")

                info(f"[DEBUG Gemini POST RESPONSE] ========== Gemini POST 응답 끝 ==========")

        except Exception as e:
            info(f"[ERROR] 응답 처리 오류: {e}")
            traceback.print_exc()