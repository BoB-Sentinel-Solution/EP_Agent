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

    
    TARGET_PATHS = ["/chat/completions", "/responses"]
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
            "interface": "llm" | "mcp",
            "context": { ... } (변조에 필요한 정보)
        }
        """
        # 1) '/responses' 경로 형식: {"input": [...]}
        if "input" in body_json:
            return self._extract_from_input_format(body_json)
        
        # 2) '/chat/completions' 경로 형식: {"messages": [...]}
        elif "messages" in body_json:
            return self._extract_from_messages_format(body_json)
        
        # 3) 백업 필드
        return self._extract_from_fallback_fields(body_json)

    def _extract_from_input_format(self, body_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        /responses 형식에서 프롬프트 추출
        {"input": [{"role": "user", "content": [{"type": "input_text", "text": "..."}]}]}
        """
        input_list = body_json.get("input")
        if not isinstance(input_list, list):
            return None
        
        # 역순으로 순회하여 마지막 user 메시지 찾기
        for i, item in reversed(list(enumerate(input_list))):
            if not isinstance(item, dict):
                continue
            
            role = (item.get("role") or "").lower()
            if role != "user":
                continue
            
            # content는 리스트 형식
            content = item.get("content")
            if not isinstance(content, list):
                continue
            
            # content 리스트에서 input_text 타입 찾기
            for j, content_item in enumerate(content):
                if not isinstance(content_item, dict):
                    continue
                
                if content_item.get("type") == "input_text":
                    text = content_item.get("text", "")
                    if text and text.strip():
                        prompt = self._normalize_text(text)
                        if prompt:
                            print(f"[VSC_ADAPTER DEBUG] ✅ 찾은 user 메시지 (input 형식) - input[{i}].content[{j}]")
                            print(f"[VSC_ADAPTER DEBUG] 해당 메시지 내용: {prompt[:100]}...")
                            # 참고: 현재 /responses 형식에서는 MCP 형식이 발견되지 않아 llm으로 가정
                            return {
                                "prompt": prompt,
                                "interface": "llm", 
                                "context": {
                                    "type": "input",
                                    "input_index": i,
                                    "content_index": j
                                }
                            }
        
        return None

    def _extract_from_messages_format(self, body_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        /chat/completions 형식에서 프롬프트 추출
        {"messages": [{"role": "user", "content": "..."}]}
        """
        messages = body_json.get("messages")
        if not isinstance(messages, list):
            return None
        
        for i, msg in reversed(list(enumerate(messages))):
            if isinstance(msg, dict) and (msg.get("role") or "").lower() == "user":
                content = msg.get("content")
                text = self._content_to_text(content)
                if text and text.strip():
                    
                    # 1. MCP 형식 (Multi-Context Prompt) 확인
                    if "<toolReferences>" in text:
                        mcp_match = re.search(r"<userRequest>(.*?)</userRequest>", text, re.DOTALL)
                        if mcp_match:
                            user_request = mcp_match.group(1).strip()
                            prompt = self._normalize_text(user_request)
                            if prompt:
                                print(f"[VSC_ADAPTER DEBUG] ✅ 찾은 user 메시지 (messages 형식 - MCP) - messages[{i}]")
                                print(f"[VSC_ADAPTER DEBUG] 해당 메시지 내용: {prompt[:100]}...")
                                return {
                                    "prompt": prompt,
                                    "interface": "mcp", # MCP 인터페이스
                                    "context": {
                                        "type": "messages",
                                        "target_index": i,
                                        "mcp_format": True # MCP 형식임을 표시
                                    }
                                }
                        # <userRequest>가 없더라도, <toolReferences>가 있다면 전체 content를 프롬프트로 보고 mcp 인터페이스를 사용하도록 처리 (대안)
                        else:
                             prompt = self._normalize_text(text)
                             if prompt:
                                print(f"[VSC_ADAPTER DEBUG] ✅ 찾은 user 메시지 (messages 형식 - MCP/userRequest 없음) - messages[{i}]")
                                print(f"[VSC_ADAPTER DEBUG] 해당 메시지 내용: {prompt[:100]}...")
                                return {
                                    "prompt": prompt,
                                    "interface": "mcp", # MCP 인터페이스
                                    "context": {
                                        "type": "messages",
                                        "target_index": i,
                                        "mcp_format": True,
                                        "mcp_fallback": True # userRequest 추출에 실패했음을 표시
                                    }
                                }
                    
                    # 2. 일반 LLM 형식
                    prompt = self._normalize_text(text)
                    if prompt:
                        print(f"[VSC_ADAPTER DEBUG] ✅ 찾은 user 메시지 (messages 형식 - 일반 LLM) - messages[{i}]")
                        print(f"[VSC_ADAPTER DEBUG] 해당 메시지 내용: {prompt[:100]}...")
                        return {
                            "prompt": prompt,
                            "interface": "llm", # 일반 LLM 인터페이스
                            "context": {
                                "type": "messages",
                                "target_index": i,
                                "mcp_format": False
                            }
                        }
        
        return None

    def _extract_from_fallback_fields(self, body_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """백업 필드에서 프롬프트 추출"""
        for key in ("prompt", "input", "input_text"):
            if key in body_json:
                text = self._content_to_text(body_json.get(key))
                if text and text.strip():
                    prompt = self._normalize_text(text)
                    if prompt:
                        # 백업 필드는 LLM으로 가정
                        return {
                            "prompt": prompt,
                            "interface": "llm",
                            "context": {
                                "type": "fallback",
                                "target_key": key
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
            print(f"[VSC_ADAPTER DEBUG] modify_request_data 호출됨")
            print(f"[VSC_ADAPTER DEBUG] new_prompt: {new_prompt[:100]}...")
            print(f"[VSC_ADAPTER DEBUG] context: {context}")
            
            context_type = context.get("type")

            # 1) /responses 형식 변조
            if context_type == "input":
                input_index = context.get("input_index")
                content_index = context.get("content_index")
                
                # ... (이전 코드와 동일, input 형식 변조)
                if input_index is None or content_index is None:
                    print(f"[VSC_ADAPTER] input_index 또는 content_index가 None")
                    return False, None
                
                if "input" not in body_json:
                    print(f"[VSC_ADAPTER] body_json에 'input' 키가 없습니다")
                    return False, None
                
                input_list = body_json["input"]
                if not isinstance(input_list, list) or input_index >= len(input_list):
                    print(f"[VSC_ADAPTER] input이 리스트가 아니거나 인덱스 범위 초과")
                    return False, None
                
                target_input = input_list[input_index]
                if not isinstance(target_input, dict):
                    print(f"[VSC_ADAPTER] target_input이 dict가 아닙니다")
                    return False, None
                
                role = (target_input.get("role") or "").lower()
                print(f"[VSC_ADAPTER DEBUG] input[{input_index}] role={role}")
                
                if role != "user":
                    print(f"[VSC_ADAPTER] ❌ role이 'user'가 아닙니다: {role}")
                    return False, None
                
                content_list = target_input.get("content")
                if not isinstance(content_list, list) or content_index >= len(content_list):
                    print(f"[VSC_ADAPTER] content가 리스트가 아니거나 인덱스 범위 초과")
                    return False, None
                
                target_content = content_list[content_index]
                if not isinstance(target_content, dict):
                    print(f"[VSC_ADAPTER] target_content가 dict가 아닙니다")
                    return False, None
                
                # 변조 전 확인
                original_text = target_content.get("text", "")
                print(f"[VSC_ADAPTER DEBUG] 변조 전 text: {str(original_text)[:200]}...")
                
                # 변조
                target_content["text"] = new_prompt
                
                print(f"[VSC_ADAPTER DEBUG] 변조 후 text: {target_content['text'][:200]}...")


            # 2) /chat/completions 형식 변조
            elif context_type == "messages":
                target_index = context.get("target_index")
                if target_index is None:
                    print(f"[VSC_ADAPTER] target_index가 None입니다")
                    return False, None
                
                if "messages" not in body_json:
                    print(f"[VSC_ADAPTER] body_json에 'messages' 키가 없습니다")
                    return False, None
                    
                messages = body_json["messages"]
                if not isinstance(messages, list) or target_index >= len(messages):
                    print(f"[VSC_ADAPTER] messages가 리스트가 아니거나 인덱스 범위 초과")
                    return False, None
                
                target_message = messages[target_index]
                if not isinstance(target_message, dict):
                    print(f"[VSC_ADAPTER] target_message가 dict가 아닙니다")
                    return False, None
                    
                role = (target_message.get("role") or "").lower()
                print(f"[VSC_ADAPTER DEBUG] messages[{target_index}] role={role}")
                
                if role != "user":
                    print(f"[VSC_ADAPTER] ❌ role이 'user'가 아닙니다: {role}")
                    return False, None
                
                original_content = target_message.get("content", "")
                
                # 2-1) MCP 형식 변조 (Context에서 mcp_format이 True인 경우)
                if context.get("mcp_format"):
                    if not isinstance(original_content, str):
                        print(f"[VSC_ADAPTER] MCP 형식 변조 실패: content가 문자열이 아닙니다.")
                        return False, None
                        
                    print(f"[VSC_ADAPTER DEBUG] ⚙️ MCP 형식 변조 시작")
                    
                    # <userRequest>...</userRequest> 내용을 새로운 프롬프트로 대체
                    # 추출에 실패하여 mcp_fallback이 True인 경우, 원본 content를 통째로 대체
                    if context.get("mcp_fallback"):
                         print(f"[VSC_ADAPTER DEBUG] ⚠️ MCP Fallback: 전체 content를 새로운 프롬프트로 대체합니다.")
                         modified_content = new_prompt
                         
                    else:
                        # new_prompt를 <userRequest> 태그 사이에 넣어 대체
                        replacement = f"<userRequest>\n{new_prompt}\n</userRequest>"
                        modified_content, count = re.subn(
                            r"<userRequest>.*?</userRequest>", 
                            replacement, 
                            original_content, 
                            count=1, 
                            flags=re.DOTALL
                        )

                        if count == 0:
                            print(f"[VSC_ADAPTER] MCP 형식 변조 실패: <userRequest> 태그를 찾지 못했습니다. 전체 content를 대체합니다.")
                            # 혹시 모를 상황에 대비하여 전체 content를 대체
                            modified_content = new_prompt
                        elif count > 1:
                            # 1개만 대체되어야 함 (re.subn의 count=1 덕분에 걱정할 필요 없음)
                            print(f"[VSC_ADAPTER] ⚠️ MCP 형식 변조 경고: <userRequest> 태그가 1개 이상 발견되었습니다.")


                    target_message["content"] = modified_content
                    print(f"[VSC_ADAPTER DEBUG] 변조 전 content: {str(original_content)[:200]}...")
                    print(f"[VSC_ADAPTER DEBUG] 변조 후 content: {target_message['content'][:200]}...")
                    
                # 2-2) 일반 LLM 형식 변조 (이전 코드와 동일)
                else:
                    print(f"[VSC_ADAPTER DEBUG] ⚙️ 일반 LLM 형식 변조 시작")
                    print(f"[VSC_ADAPTER DEBUG] 변조 전 content: {str(original_content)[:200]}...")
                    
                    target_message["content"] = new_prompt
                    
                    print(f"[VSC_ADAPTER DEBUG] 변조 후 content: {target_message['content'][:200]}...")


            # 3) 백업 필드 변조
            elif context_type == "fallback":
                # ... (이전 코드와 동일)
                target_key = context.get("target_key")
                if not target_key:
                    print(f"[VSC_ADAPTER] target_key가 없습니다")
                    return False, None
                
                print(f"[VSC_ADAPTER DEBUG] 변조 전 {target_key}: {str(body_json.get(target_key, ''))[:200]}...")
                body_json[target_key] = new_prompt
                print(f"[VSC_ADAPTER DEBUG] 변조 후 {target_key}: {body_json[target_key][:200]}...")
                
            else:
                print(f"[VSC_ADAPTER] 알 수 없는 컨텍스트 타입: {context_type}")
                return False, None

            # 수정된 딕셔너리를 bytes로 직렬화
            modified_content_str = json.dumps(body_json, ensure_ascii=False)
            modified_content = modified_content_str.encode("utf-8")
            
            print(f"[VSC_ADAPTER DEBUG] 직렬화된 content 길이: {len(modified_content)}")
            
            # 변조 검증
            if new_prompt in modified_content_str:
                print(f"[VSC_ADAPTER DEBUG] ✅ 변조된 프롬프트가 JSON에 포함되어 있습니다!")
            else:
                print(f"[VSC_ADAPTER DEBUG] ❌ 변조된 프롬프트가 JSON에 없습니다!")
            
            print(f"[VSC_ADAPTER DEBUG] 직렬화된 content 미리보기: {modified_content[:300]}...")
            
            return True, modified_content

        except Exception as e:
            print(f"[VSC_ADAPTER] modify_request_data 오류: {e}")
            import traceback
            traceback.print_exc()
            return False, None

    # ---------- Internals ----------
    def _is_target_request(self, flow: http.HTTPFlow) -> bool:
        try:
            if flow.request.method.upper() != "POST":
                return False
            path = flow.request.path.split("?")[0].rstrip("/").lower()
            
            # [수정] 여러 경로 지원
            for target_path in self.TARGET_PATHS:
                target = target_path.rstrip("/").lower()
                if path.endswith(target):
                    return True
            return False
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