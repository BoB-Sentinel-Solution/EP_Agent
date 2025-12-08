# app_parser/adapter/vscode.py
import json
import re
from typing import Any, Dict, Optional, List, Union, Tuple
from mitmproxy import http

TextLike = Union[str, Dict[str, Any], List[Any]]

class VSCodeCopilotAdapter:
    """
    [리팩토링]
    ChatGPTAdapter 스타일을 적용한 순수 함수 기반 어댑터.
    - 파싱/변조 함수는 'flow' 객체를 직접 다루지 않고 dict/bytes만 반환합니다.
    - 'flow'에서 dict를 추출하고, dict에서 'bytes'를 'flow'에 적용하는
      "부수 효과"는 상위 핸들러(app_main)의 책임입니다.
    """

    TARGET_PATH = "/chat/completions"
    MAX_PROMPT_LEN = 8000

    # -------------------------------
    # 1. 파싱 (flow -> dict)
    # -------------------------------
    def parse_flow_to_json(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        'flow' 객체를 받아, 대상 요청이 맞으면 JSON(dict)을 반환합니다.
        이 함수가 유일하게 'flow' 객체를 직접 다룹니다.
        """
        if not self._is_target_request(flow):
            return None
        return self._parse_body_json(flow)

    # -------------------------------
    # 2. 프롬프트 추출 (dict -> str, context)
    # -------------------------------
    def extract_prompt(self, body_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        [순수 함수]
        파싱된 JSON(dict)을 받아, 프롬프트와 컨텍스트를 반환합니다.
        
        반환:
        {
            "prompt": str,
            "interface": "llm",
            "context": { ... } (변조에 필요한 정보)
        }
        """
        # 1) 'messages' 기반
        messages = body_json.get("messages")
        if isinstance(messages, list):
            for i, msg in reversed(list(enumerate(messages))): # [수정] 인덱스(i)도 함께 추적
                if isinstance(msg, dict) and (msg.get("role") or "").lower() == "user":
                    content = msg.get("content")
                    text = self._content_to_text(content)
                    if text and text.strip():
                        prompt = self._normalize_text(text)
                        if prompt:
                            return {
                                "prompt": prompt,
                                "interface": "llm",
                                "context": {
                                    "type": "messages",
                                    "target_index": i # 수정할 메시지의 인덱스
                                }
                            }

        # 2) '백업 필드' 기반
        for key in ("prompt", "input", "input_text"):
            if key in body_json:
                text = self._content_to_text(body_json.get(key))
                if text and text.strip():
                    prompt = self._normalize_text(text)
                    if prompt:
                        return {
                            "prompt": prompt,
                            "interface": "llm",
                            "context": {
                                "type": "fallback",
                                "target_key": key # 수정할 최상위 키
                            }
                        }
        
        return None

    # -------------------------------
    # 3. 프롬프트 변조 (dict, context, str -> bytes)
    # -------------------------------
    def modify_request_data(self, 
                            body_json: Dict[str, Any], 
                            context: Dict[str, Any], 
                            new_prompt: str) -> Tuple[bool, Optional[bytes]]:
        """
        [순수 함수]
        원본 JSON, 컨텍스트, 새 프롬프트를 받아,
        변조된 요청 본문(bytes)을 반환합니다.
        """
        try:
            context_type = context.get("type")

            if context_type == "messages":
                target_index = context.get("target_index")
                if target_index is None:
                    return False, None
                
                # 'messages' 내부의 content를 변조
                # [수정된 부분]: <prompt> 태그를 제거하고 new_prompt만 대입
                # new_prompt는 이미 마스킹된(예: 'EMAIL') 값이므로, 그대로 사용합니다.
                body_json["messages"][target_index]["content"] = new_prompt # <--- 이 라인을 수정
                
            elif context_type == "fallback":
                target_key = context.get("target_key")
                if not target_key:
                    return None
                
                # 최상위 키(e.g. 'prompt')의 값을 변조 (이 부분은 그대로 유지)
                body_json[target_key] = new_prompt
                
            else:
                return False, None # 알 수 없는 컨텍스트 타입

            # 수정된 딕셔너리를 bytes로 직렬화하여 반환
            modified_content_str = json.dumps(body_json, ensure_ascii=False)
            modified_content = modified_content_str.encode("utf-8")
            
            return True, modified_content

        except Exception as e:
            print(f"[VSC_ADAPTER] modify_request_data 오류: {e}")
            return False, None

    # ---------- Internals (이전과 동일) ----------
    def _is_target_request(self, flow: http.HTTPFlow) -> bool:
        try:
            if flow.request.method.upper() != "POST":
                return False
            path = flow.request.path.split("?")[0].rstrip("/").lower()
            target = self.TARGET_PATH.rstrip("/").lower()
            return path.endswith(target)
        except Exception:
            return False

    def _parse_body_json(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        content = getattr(flow.request, "content", b"") or b""
        if not content:
            return None
        try:
            raw = content.decode("utf-8", errors="ignore").strip()
            if not raw:
                return None
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def _content_to_text(self, content: TextLike) -> Optional[str]:
        # (이전과 동일하게 유지)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    summary = self._summarize_obj_content(item)
                    if summary:
                        parts.append(summary)
            return "\n".join(parts) if parts else None
        if isinstance(content, dict):
            for k in ("text", "value", "content"):
                if k in content and isinstance(content[k], str):
                    return content[k]
            return self._summarize_obj_content(content)
        return None

    def _summarize_obj_content(self, obj: Dict[str, Any]) -> Optional[str]:
        # (이전과 동일하게 유지)
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
            keys = ", ".join(list(obj.keys())[:3])
            return f"[{t} {keys}]"
        except Exception:
            return "[object]"
            
    def _normalize_text(self, text: Optional[str]) -> Optional[str]:
        # (이전과 동일하게 유지)
        if not isinstance(text, str):
            return None
        s = text.strip()
        if s.startswith("<prompt>") and s.endswith("</prompt>"):
            s = s[8:-9].strip() 
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = re.sub(r"[ \t\f\v]+", " ", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
        
        s = s.strip()
        return s or None