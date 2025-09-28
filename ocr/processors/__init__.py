"""
LLM별 파일 처리 프로세서 패키지

각 LLM 서비스별로 파일 업로드를 감지하고 OCR 처리하여 보안 키워드를 검사하는
프로세서들을 관리합니다.

지원하는 LLM:
- ChatGPT (files.oaiusercontent.com)
- Claude (추후 구현)
- Gemini (추후 구현)
- DeepSeek (추후 구현)
- Groq (추후 구현)
"""

from .base_processor import BaseLLMProcessor
from .chatgpt_processor import ChatGPTProcessor

__all__ = [
    'BaseLLMProcessor',
    'ChatGPTProcessor'
]