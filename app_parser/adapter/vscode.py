# app_parser/adapter/vscode.py
import json
import re
from typing import Any, Dict, Optional, List, Union
from mitmproxy import http

TextLike = Union[str, Dict[str, Any], List[Any]]

class VSCodeCopilotAdapter:
    """
    VSCode Copilot 계열 요청에서 프롬프트만 추출하는 어댑터.
    - 대상: path가 /chat/completions 로 끝나는 POST 요청(쿼리/대소문자 무시)
    - body: OpenAI 호환 포맷(messages / prompt / input / input_text)
    반환: {"prompt": str, "interface": "llm"} 또는 None
    """

    TARGET_PATH = "/chat/completions"
    MAX_PROMPT_LEN = 8000  # 방어적 컷

    # ---------- Public API ----------
    def extract_prompt(self, flow: http.HTTPFlow) -> Optional[Dict[str, str]]:
        if not self._is_target_request(flow):
            return None

        body = self._parse_body_json(flow)
        if not body:
            return None

        # 1) messages 기반
        prompt = self._extract_prompt_from_messages(body)
        if not prompt:
            # 2) 백업 필드 기반
            prompt = self._extract_from_fallback_fields(body)

        prompt = self._normalize_text(prompt)
        if not prompt:
            return None

        # 너무 긴 입력은 컷
        if len(prompt) > self.MAX_PROMPT_LEN:
            prompt = prompt[: self.MAX_PROMPT_LEN] + "…"

        return {"prompt": prompt, "interface": "llm"}

    # ---------- Internals ----------
    def _is_target_request(self, flow: http.HTTPFlow) -> bool:
        try:
            if flow.request.method.upper() != "POST":
                return False
            # 경로 정규화: 쿼리 제거, 소문자, 뒤 슬래시 제거
            path = flow.request.path.split("?")[0].rstrip("/").lower()
            target = self.TARGET_PATH.rstrip("/").lower()
            # /v1/chat/completions 같은 변형도 허용: 경로 끝 매칭
            return path.endswith(target)
        except Exception:
            return False

    def _parse_body_json(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        content = getattr(flow.request, "content", b"") or b""
        if not content:
            return None
        try:
            # 일반적으로 utf-8이지만, 깨질 가능성 대비 ignore
            raw = content.decode("utf-8", errors="ignore")
            raw = raw.strip()
            if not raw:
                return None
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    # ---- messages 계열 처리 ----
    def _extract_prompt_from_messages(self, body: Dict[str, Any]) -> Optional[str]:
        messages = body.get("messages")
        if not isinstance(messages, list):
            return None

        # [수정] 배열을 역순으로 탐색하여 *마지막* user 메시지를 찾습니다.
        for msg in reversed(messages):
            if not isinstance(msg, dict):
                continue
            role = (msg.get("role") or "").lower()
            if role != "user":
                continue

            # [수정] 첫 번째로 찾은(즉, 가장 마지막) user 메시지의 content를 사용합니다.
            content = msg.get("content")
            text = self._content_to_text(content)
            
            # [수정] 텍스트를 찾으면 바로 반환합니다.
            if text and text.strip():
                return text

        # [수정] user_chunks 대신, user 메시지를 못 찾았으면 None 반환
        return None

    # ---- 백업 필드 처리 ----
    def _extract_from_fallback_fields(self, body: Dict[str, Any]) -> Optional[str]:
        # OpenAI 호환 백업 필드 후보
        for key in ("prompt", "input", "input_text"):
            if key in body:
                text = self._content_to_text(body.get(key))
                if text and text.strip():
                    return text
        return None

    # ---- content를 텍스트로 안전 변환 ----
    def _content_to_text(self, content: TextLike) -> Optional[str]:
        # 1) 문자열
        if isinstance(content, str):
            return content

        # 2) 배열인 경우: 문자열 요소만 이어붙이고, 객체는 요약
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    # 이미지/파일/툴 호출 등은 간략 표현
                    summary = self._summarize_obj_content(item)
                    if summary:
                        parts.append(summary)
            return "\n".join(parts) if parts else None

        # 3) 객체인 경우: text / value / content 등의 후보 키 탐색
        if isinstance(content, dict):
            for k in ("text", "value", "content"):
                if k in content and isinstance(content[k], str):
                    return content[k]
            # 기타 객체는 요약
            return self._summarize_obj_content(content)

        return None

    def _summarize_obj_content(self, obj: Dict[str, Any]) -> Optional[str]:
        # 이미지/파일/툴 콜 등을 텍스트화(최소 정보)
        try:
            t = obj.get("type") or obj.get("kind") or "object"
            if t == "image_url":
                url = obj.get("image_url", {}).get("url") if isinstance(obj.get("image_url"), dict) else obj.get("image_url")
                return f"[image:{url or '…'}]"
            if t in ("input_image", "image"):
                return "[image]"
            if t in ("file", "input_file"):
                return f"[file:{obj.get('name') or obj.get('id') or '…'}]"
            if t in ("tool_call", "function_call", "tool"):
                name = obj.get("name") or obj.get("tool_name") or "tool"
                return f"[tool:{name}]"
            # 알 수 없는 객체는 key 일부만
            keys = ", ".join(list(obj.keys())[:3])
            return f"[{t} {keys}]"
        except Exception:
            return "[object]"

    def _normalize_text(self, text: Optional[str]) -> Optional[str]:
        if not isinstance(text, str):
            return None
        
        s = text.strip()

        # [수정] <prompt>...</prompt> 태그가 감싸고 있으면 제거합니다.
        if s.startswith("<prompt>") and s.endswith("</prompt>"):
            # s[len("<prompt>") : -len("</prompt>")] 와 동일
            s = s[8:-9].strip() 

        # 제어문자 정리 + 다중 공백 축약
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = re.sub(r"[ \t\f\v]+", " ", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
        s = s.strip()
        return s or None
