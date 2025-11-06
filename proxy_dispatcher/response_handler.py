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
    """
    try:
        info(f"[NOTIFY] 알림창 표시 시작 - {host}")

        # 안전 가드: Tk 루트가 없다면 생성/숨김
        root = tk._default_root
        if root is None:
            root = tk.Tk()
            root.withdraw()

        # 커스텀 알림창 생성
        dialog = tk.Toplevel(root)
        dialog.title("프롬프트 변조 알림")
        dialog.geometry("500x450")
        dialog.resizable(False, False)
        dialog.attributes('-topmost', True)
        dialog.configure(bg='#ffffff')

        max_length = 200
        original_display = (original_prompt[:max_length] + ("..." if len(original_prompt) > max_length else ""))
        modified_display = (modified_prompt[:max_length] + ("..." if len(modified_prompt) > max_length else ""))

        header_frame = tk.Frame(dialog, bg='#667eea', height=70)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)

        icon_label = tk.Label(header_frame, text="🔒", font=('Segoe UI', 24), bg='#667eea', fg='#ffffff')
        icon_label.pack(pady=(10, 0))

        title_label = tk.Label(header_frame, text="프롬프트가 변조되어 전송됩니다",
                               font=('Segoe UI', 11, 'bold'), bg='#667eea', fg='#ffffff')
        title_label.pack(pady=(3, 10))

        content_frame = tk.Frame(dialog, bg='#ffffff')
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)

        host_container = tk.Frame(content_frame, bg='#ffffff')
        host_container.pack(fill='x', pady=(0, 15))
        host_icon = tk.Label(host_container, text="🌐", font=('Segoe UI', 10), bg='#ffffff', fg='#667eea')
        host_icon.pack(side='left', padx=(0, 6))
        host_label = tk.Label(host_container, text=f"호스트: {host}", font=('Segoe UI', 9),
                              bg='#ffffff', fg='#495057', anchor='w')
        host_label.pack(side='left', fill='x', expand=True)

        separator1 = tk.Frame(content_frame, bg='#e9ecef', height=1)
        separator1.pack(fill='x', pady=(0, 15))

        modified_label = tk.Label(content_frame, text="프롬프트 변경", font=('Segoe UI', 10, 'bold'),
                                  bg='#ffffff', fg='#e53e3e', anchor='w')
        modified_label.pack(fill='x', pady=(0, 6))

        modified_frame = tk.Frame(content_frame, bg='#fffbeb', relief='flat', bd=1,
                                  highlightbackground='#fbbf24', highlightthickness=2)
        modified_frame.pack(fill='x', pady=(0, 20))

        modified_text = tk.Text(modified_frame, height=4, wrap='word', font=('Segoe UI', 9),
                                bg='#fffbeb', fg='#92400e', relief='flat', padx=10, pady=10, state='normal',
                                borderwidth=0)
        modified_text.pack(fill='x')
        modified_text.insert('1.0', modified_display)
        modified_text.configure(state='disabled')

        info_frame = tk.Frame(content_frame, bg='#eef2ff', relief='flat', bd=0)
        info_frame.pack(fill='x', pady=(0, 20))
        info_label = tk.Label(info_frame,
                              text="💡 [확인]을 누르면 변조된 프롬프트가 LLM 서버로 전송됩니다.",
                              font=('Segoe UI', 8), bg='#eef2ff', fg='#4c51bf', padx=10, pady=8, anchor='w')
        info_label.pack(fill='x')

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

        button_container = tk.Frame(button_frame, bg='#f8f9fa')
        button_container.pack(expand=True)

        confirm_button = tk.Button(button_container, text="✓  확인하고 전송하기",
                                   font=('Segoe UI', 10, 'bold'), bg='#667eea', fg='#ffffff',
                                   activebackground='#5a67d8', activeforeground='#ffffff',
                                   relief='flat', bd=0, padx=40, pady=10, cursor='hand2',
                                   command=on_confirm)
        confirm_button.pack()
        confirm_button.bind('<Enter>', on_enter)
        confirm_button.bind('<Leave>', on_leave)

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        #dialog.transient(root)
        # transient(root) 제거 - 독립적인 창으로 표시하여 안정성 확보
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
        notification_callback: Optional[Callable] = None
    ):
        self.llm_hosts = llm_hosts
        self.app_hosts = app_hosts
        self.notification_callback = notification_callback
        info("[INIT] Response Handler 초기화")

    def process(self, flow: http.HTTPFlow):
        """응답 처리 메인 로직 (TODO)"""
        pass
