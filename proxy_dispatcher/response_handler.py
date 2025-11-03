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
        dialog.geometry("700x700")  # 크기 증가
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

        # 상단 헤더 프레임 (그라디언트 효과를 위한 더 큰 영역)
        header_frame = tk.Frame(dialog, bg='#667eea', height=100)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # 경고 아이콘 및 제목
        icon_label = tk.Label(
            header_frame,
            text="🔒",
            font=('Segoe UI', 32),
            bg='#667eea',
            fg='#ffffff'
        )
        icon_label.pack(pady=(15, 0))
        
        title_label = tk.Label(
            header_frame,
            text="프롬프트가 변조되어 전송됩니다",
            font=('Segoe UI', 13, 'bold'),
            bg='#667eea',
            fg='#ffffff'
        )
        title_label.pack(pady=(5, 15))
        
        # 메인 컨텐츠 프레임
        content_frame = tk.Frame(dialog, bg='#ffffff')
        content_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # 호스트 정보 (더 세련된 디자인)
        host_container = tk.Frame(content_frame, bg='#ffffff')
        host_container.pack(fill='x', pady=(0, 20))
        
        host_icon = tk.Label(
            host_container,
            text="🌐",
            font=('Segoe UI', 12),
            bg='#ffffff',
            fg='#667eea'
        )
        host_icon.pack(side='left', padx=(0, 8))
        
        host_label = tk.Label(
            host_container,
            text=f"호스트: {host}",
            font=('Segoe UI', 10),
            bg='#ffffff',
            fg='#495057',
            anchor='w'
        )
        host_label.pack(side='left', fill='x', expand=True)
        
        # 구분선
        separator1 = tk.Frame(content_frame, bg='#e9ecef', height=1)
        separator1.pack(fill='x', pady=(0, 20))
        
        # 원본 프롬프트 섹션
        original_label = tk.Label(
            content_frame,
            text="📄 원본 프롬프트",
            font=('Segoe UI', 11, 'bold'),
            bg='#ffffff',
            fg='#2d3748',
            anchor='w'
        )
        original_label.pack(fill='x', pady=(0, 8))
        
        original_frame = tk.Frame(content_frame, bg='#f7fafc', relief='flat', bd=1, highlightbackground='#e2e8f0', highlightthickness=1)
        original_frame.pack(fill='x', pady=(0, 20))
        
        original_text = tk.Text(
            original_frame,
            height=5,  # 높이 증가
            wrap='word',
            font=('Segoe UI', 9),
            bg='#f7fafc',
            fg='#2d3748',
            relief='flat',
            padx=12,
            pady=12,
            state='normal',
            borderwidth=0
        )
        original_text.pack(fill='x')
        original_text.insert('1.0', original_display)
        original_text.configure(state='disabled')
        
        # 변조된 프롬프트 섹션
        modified_label = tk.Label(
            content_frame,
            text="⚠️ 변조된 프롬프트",
            font=('Segoe UI', 11, 'bold'),
            bg='#ffffff',
            fg='#e53e3e',
            anchor='w'
        )
        modified_label.pack(fill='x', pady=(0, 8))
        
        modified_frame = tk.Frame(content_frame, bg='#fffbeb', relief='flat', bd=1, highlightbackground='#fbbf24', highlightthickness=2)
        modified_frame.pack(fill='x', pady=(0, 25))  # 간격 증가
        
        modified_text = tk.Text(
            modified_frame,
            height=5,  # 높이 증가
            wrap='word',
            font=('Segoe UI', 9),
            bg='#fffbeb',
            fg='#92400e',
            relief='flat',
            padx=12,
            pady=12,
            state='normal',
            borderwidth=0
        )
        modified_text.pack(fill='x')
        modified_text.insert('1.0', modified_display)
        modified_text.configure(state='disabled')
        
        # 안내 메시지 (더 눈에 띄게)
        info_frame = tk.Frame(content_frame, bg='#eef2ff', relief='flat', bd=0)
        info_frame.pack(fill='x', pady=(0, 30))  # 하단 간격 증가
        
        info_label = tk.Label(
            info_frame,
            text="💡 [확인]을 누르면 변조된 프롬프트가 LLM 서버로 전송됩니다.",
            font=('Segoe UI', 9),
            bg='#eef2ff',
            fg='#4c51bf',
            padx=12,
            pady=10,
            anchor='w'
        )
        info_label.pack(fill='x')
        
        # 하단 버튼 프레임 (더 넓은 영역)
        button_frame = tk.Frame(dialog, bg='#f8f9fa', height=90)  # 높이 증가
        button_frame.pack(fill='x', padx=0, pady=0)
        button_frame.pack_propagate(False)
        
        def on_confirm():
            info(f"[NOTIFY] 사용자 확인 완료 - 요청 계속 진행")
            dialog.destroy()
        
        def on_enter(e):
            confirm_button.config(bg='#5a67d8')
        
        def on_leave(e):
            confirm_button.config(bg='#667eea')
        
        # 확인 버튼 (훨씬 더 크고 눈에 띄게)
        button_container = tk.Frame(button_frame, bg='#f8f9fa')
        button_container.pack(expand=True)
        
        confirm_button = tk.Button(
            button_container,
            text="✓  확인하고 전송하기",
            font=('Segoe UI', 12, 'bold'),
            bg='#667eea',
            fg='#ffffff',
            activebackground='#5a67d8',
            activeforeground='#ffffff',
            relief='flat',
            bd=0,
            padx=60,
            pady=15,
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