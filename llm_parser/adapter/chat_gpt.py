from llm_parser.common.utils import LLMAdapter
from mitmproxy import http
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import os
import json

UNIFIED_LOG_PATH = "./unified_request.json"

# -------------------------------
# ChatGPT Adapter (프롬프트 처리 전용)
# 파일 처리는 chatgpt_file_handler.py로 분리됨
# -------------------------------
class ChatGPTAdapter(LLMAdapter):
    def _save_unified_log(self, data: dict):
        """unified_request.json에 로그 append"""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(UNIFIED_LOG_PATH)) or ".", exist_ok=True)
            with open(UNIFIED_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[ERROR] unified_request.json 기록 실패: {e}")

    
    def extract_prompt(self, request_json: dict, host: str) -> Optional[str]:
        try:
            messages = request_json.get("messages", [])
            if not isinstance(messages, list) or not messages:
                return None

            last_message = messages[-1]
            author = last_message.get("author", {})
            role = author.get("role")
            name = author.get("name")

            # --- Case 1: user role ---
            if role == "user":
                # system_hints 체크 (agent 있으면 MCP, 없으면 LLM)
                metadata = last_message.get("metadata", {})
                system_hints = metadata.get("system_hints", [])

                has_agent = False
                if isinstance(system_hints, list):
                    has_agent = "agent" in system_hints
                elif isinstance(system_hints, str):
                    has_agent = "agent" in system_hints

                # 프롬프트 추출
                content = last_message.get("content", {})
                parts = content.get("parts", [])
                text = content.get("text")

                extracted_prompt = None
                if parts and isinstance(parts, list):
                    text_parts_list = []
                    for part in parts:
                        if isinstance(part, str):
                            text_parts_list.append(part)
                        elif isinstance(part, dict) and part.get("content_type") == "text":
                            text_parts_list.append(part.get("content", ""))
                    if text_parts_list:
                        extracted_prompt = " ".join(text_parts_list)[:1000]
                        print(f"[DEBUG ChatGPTAdapter] user role 프롬프트 추출: {extracted_prompt[:50]}...")

                if not extracted_prompt and text and isinstance(text, str):
                    extracted_prompt = text[:1000]
                    print(f"[DEBUG ChatGPTAdapter] user role text 추출: {extracted_prompt[:50]}...")

                # --- [!!!] 핵심 수정 지점 ---
                if extracted_prompt:
                    interface = "mcp" if has_agent else "llm"
                    
                    # [수정] 로그를 직접 저장하는 대신,
                    # 상위 로거(llm_main.py)가 처리할 dict를 반환합니다.
                    result = {
                        "prompt": extracted_prompt,
                        # llm_main.py가 attachment를 기대할 수 있으므로 호환성을 위해 추가
                        "attachment": {"format": None, "data": None}, 
                        "interface": interface
                    }
                    print(f"[DEBUG ChatGPTAdapter] 프롬프트 추출 완료 (interface={interface}): {extracted_prompt[:50]}...")
                    # [수정] 문자열이 아닌 dict(result)를 반환
                    return result 
                
                # [수정] 프롬프트가 없는 경우
                return None

            # --- Case 2: 기타 ---
            print(f"[DEBUG ChatGPTAdapter] role={role}, name={name} => 프롬프트 추출 대상 아님")
            return None

        except Exception as e:
            print(f"[DEBUG ChatGPTAdapter] extract_prompt 예외 발생: {e}")
            return None
        
        

    def should_modify(self, host: str, content_type: str) -> bool:
        """ChatGPT 변조 대상 확인"""
        return (
            "chatgpt.com" in host and
            "application/json" in content_type
        )



    def modify_request_data(self, request_data: dict, modified_prompt: str, host: str) -> Tuple[bool, Optional[bytes]]:
        """ChatGPT 요청 데이터 변조 (멀티모달 대응 + 디버그 로그 강화)"""
        try:
            print(f"[DEBUG] modify_request_data 시작 - host={host}")

            messages = request_data.get("messages", [])
            if not messages:
                print("[DEBUG] 메시지 없음 - 수정 불가")
                return False, None

            last_message = messages[-1]
            author = last_message.get("author", {})

            if author.get("role") != "user":
                print("[DEBUG] 마지막 메시지가 user가 아님 - 수정 스킵")
                return False, None

            content = last_message.get("content", {})
            parts = content.get("parts", [])
            
            
            # [수정] GPT-4o 등 parts가 dict일 경우도 처리
            if parts:
                if isinstance(parts[0], str):
                    request_data["messages"][-1]["content"]["parts"][0] = modified_prompt
                    modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes
                elif isinstance(parts[0], dict) and parts[0].get("content_type") == "text":
                    request_data["messages"][-1]["content"]["parts"][0]["content"] = modified_prompt
                    modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                    return True, modified_bytes

            # [수정] 'text' 필드만 있는 경우
            elif "text" in content:
                request_data["messages"][-1]["content"]["text"] = modified_prompt
                modified_bytes = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
                return True, modified_bytes

            return False, None
        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None



            print(f"[DEBUG] parts 구조: {parts}")
            print(f"[DEBUG] parts 개수: {len(parts)}")

            if not parts:
                print("[DEBUG] parts 없음 - 수정 불가")
                return False, None

            replaced = False

            # parts 전체를 순회하며 문자열 part 찾아 수정
            for idx, part in enumerate(parts):
                print(f"[DEBUG] part[{idx}] type: {type(part)}")

                if isinstance(part, str):
                    print(f"[DEBUG] 텍스트 part 발견! index={idx}")
                    parts[idx] = modified_prompt
                    replaced = True
                    break

            if not replaced:
                print("[DEBUG] 치환할 문자열 part 없음 - 멀티모달 only?")
                return False, None

            # JSON → 바이너리 변환
            modified_content = json.dumps(
                request_data,
                ensure_ascii=False
            ).encode('utf-8')

            print(f"[DEBUG] 수정 완료! 최종 바이트 길이={len(modified_content)}")
            return True, modified_content

        except Exception as e:
            print(f"[ERROR] ChatGPT 변조 실패: {e}")
            return False, None
