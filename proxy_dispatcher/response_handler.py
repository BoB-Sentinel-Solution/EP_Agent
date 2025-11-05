#!/usr/bin/env python3
"""
Response Handler - 응답 트래픽 처리 및 알림 모듈
"""
import tkinter as tk
from tkinter import messagebox
from typing import Set, Optional, Callable
from mitmproxy import http, ctx

# mitmproxy 로거 사용
log = ctx.log if hasattr(ctx, 'log') else None

def info(msg):
    """로그 출력"""
    if log:
        log.info(msg)
    else:
        print(msg)


def show_modification_alert(original_prompt: str, modified_prompt: str, host: str):
    """
    변조 알림창 표시 (모달 - 블로킹)
    사용자가 확인 버튼을 누를 때까지 대기

    Args:
        original_prompt: 원본 프롬프트
        modified_prompt: 변조된 프롬프트
        host: 호스트명
    """
    try:
        info(f"[NOTIFY] 알림창 표시 시작 - {host}")

        # 커스텀 알림창 생성
        dialog = tk.Toplevel()
        dialog.title("프롬프트 변조 알림")
        dialog.geometry("500x450")  # 크기 축소
        dialog.resizable(False, False)
        dialog.attributes('-topmost', True)
        
        # 배경색 설정
        dialog.configure(bg='#ffffff')
        
        # 프롬프트 길이 제한
        max_length = 200
        original_display = original_prompt[:max_length]
        if len(original_prompt) > max_length:
            original_display += "..."

        modified_display = modified_prompt[:max_length]
        if len(modified_prompt) > max_length:
            modified_display += "..."

        # 상단 헤더 프레임
        header_frame = tk.Frame(dialog, bg='#667eea', height=70)  # 높이 축소
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # 경고 아이콘 및 제목
        icon_label = tk.Label(
            header_frame,
            text="🔒",
            font=('Segoe UI', 24),  # 크기 축소
            bg='#667eea',
            fg='#ffffff'
        )
        icon_label.pack(pady=(10, 0))  # 패딩 축소
        
        title_label = tk.Label(
            header_frame,
            text="프롬프트가 변조되어 전송됩니다",
            font=('Segoe UI', 11, 'bold'),  # 크기 축소
            bg='#667eea',
            fg='#ffffff'
        )
        title_label.pack(pady=(3, 10))  # 패딩 축소
        
        # 메인 컨텐츠 프레임
        content_frame = tk.Frame(dialog, bg='#ffffff')
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)  # 패딩 축소
        
        # 호스트 정보
        host_container = tk.Frame(content_frame, bg='#ffffff')
        host_container.pack(fill='x', pady=(0, 15))  # 패딩 축소
        
        host_icon = tk.Label(
            host_container,
            text="🌐",
            font=('Segoe UI', 10),  # 크기 축소
            bg='#ffffff',
            fg='#667eea'
        )
        host_icon.pack(side='left', padx=(0, 6))
        
        host_label = tk.Label(
            host_container,
            text=f"호스트: {host}",
            font=('Segoe UI', 9),  # 크기 축소
            bg='#ffffff',
            fg='#495057',
            anchor='w'
        )
        host_label.pack(side='left', fill='x', expand=True)
        
        # 구분선
        separator1 = tk.Frame(content_frame, bg='#e9ecef', height=1)
        separator1.pack(fill='x', pady=(0, 15))  # 패딩 축소
        
        # 변조된 프롬프트 섹션
        modified_label = tk.Label(
            content_frame,
            text="프롬프트 변경",
            font=('Segoe UI', 10, 'bold'),  # 크기 축소
            bg='#ffffff',
            fg='#e53e3e',
            anchor='w'
        )
        modified_label.pack(fill='x', pady=(0, 6))  # 패딩 축소
        
        modified_frame = tk.Frame(content_frame, bg='#fffbeb', relief='flat', bd=1, highlightbackground='#fbbf24', highlightthickness=2)
        modified_frame.pack(fill='x', pady=(0, 20))  # 패딩 축소
        
        modified_text = tk.Text(
            modified_frame,
            height=4,  # 높이 축소
            wrap='word',
            font=('Segoe UI', 9),
            bg='#fffbeb',
            fg='#92400e',
            relief='flat',
            padx=10,  # 패딩 축소
            pady=10,  # 패딩 축소
            state='normal',
            borderwidth=0
        )
        modified_text.pack(fill='x')
        modified_text.insert('1.0', modified_display)
        modified_text.configure(state='disabled')
        
        # 안내 메시지
        info_frame = tk.Frame(content_frame, bg='#eef2ff', relief='flat', bd=0)
        info_frame.pack(fill='x', pady=(0, 20))  # 패딩 축소
        
        info_label = tk.Label(
            info_frame,
            text="💡 [확인]을 누르면 변조된 프롬프트가 LLM 서버로 전송됩니다.",
            font=('Segoe UI', 8),  # 크기 축소
            bg='#eef2ff',
            fg='#4c51bf',
            padx=10,  # 패딩 축소
            pady=8,  # 패딩 축소
            anchor='w'
        )
        info_label.pack(fill='x')
        
        # 하단 버튼 프레임
        button_frame = tk.Frame(dialog, bg='#f8f9fa', height=65)  # 높이 축소
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
            font=('Segoe UI', 10, 'bold'),  # 크기 축소
            bg='#667eea',
            fg='#ffffff',
            activebackground='#5a67d8',
            activeforeground='#ffffff',
            relief='flat',
            bd=0,
            padx=40,  # 패딩 축소
            pady=10,  # 패딩 축소
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
        dialog.transient()
        dialog.grab_set()
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
        notification_callback: Optional[Callable] = None
    ):
        """
        Args:
            llm_hosts: LLM 호스트 집합
            app_hosts: App/MCP 호스트 집합
            notification_callback: 알림 콜백 함수
        """
        self.llm_hosts = llm_hosts
        self.app_hosts = app_hosts
        self.notification_callback = notification_callback
        info("[INIT] Response Handler 초기화")

    def process(self, flow: http.HTTPFlow):
        """
        응답 처리 메인 로직 (TODO: 향후 확장 예정)

        Args:
            flow: mitmproxy HTTPFlow 객체
        """
        # TODO: Response 분석 로직 추가 예정
        pass