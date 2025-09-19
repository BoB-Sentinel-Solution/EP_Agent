import base64
import re
import json
from typing import List, Dict, Any, Optional

class ImageScanner:
    """HTTP 요청에서 이미지 데이터 스캔 및 추출"""
    
    @staticmethod
    def extract_images_from_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """어댑터에서 추출된 첨부파일에서 이미지 데이터 추출"""
        images = []
        
        for attachment in attachments:
            image_data = ImageScanner._process_attachment(attachment)
            if image_data:
                images.append(image_data)
        
        return images
    
    @staticmethod
    def _process_attachment(attachment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """단일 첨부파일에서 이미지 데이터 추출"""
        try:
            # base64 데이터가 있는 경우
            if attachment.get('data'):
                base64_data = attachment['data']
                # data:image/png;base64, 부분 제거
                if base64_data.startswith('data:image'):
                    base64_data = base64_data.split(',')[1]
                
                return {
                    'type': 'base64',
                    'data': base64_data,
                    'format': attachment.get('type', 'unknown')
                }
            
            # URL이 있는 경우 (나중에 다운로드 필요)
            elif attachment.get('url'):
                return {
                    'type': 'url',
                    'url': attachment['url'],
                    'format': attachment.get('type', 'unknown')
                }
                
        except Exception as e:
            print(f"첨부파일 처리 중 오류: {e}")
            
        return None
    
    @staticmethod
    def extract_base64_from_json(request_json: Dict[str, Any]) -> List[str]:
        """JSON 요청에서 직접 base64 이미지 데이터 찾기 (백업용)"""
        base64_images = []
        
        try:
            # JSON을 문자열로 변환해서 base64 패턴 찾기
            json_str = json.dumps(request_json)
            
            # base64 이미지 패턴 매칭
            patterns = [
                r'data:image/[^;]+;base64,([A-Za-z0-9+/=]+)',  # data:image/png;base64,xxx
                r'"data":"([A-Za-z0-9+/=]{100,})"',  # "data":"base64string" (긴 문자열만)
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, json_str)
                base64_images.extend(matches)
                
        except Exception as e:
            print(f"JSON에서 base64 추출 중 오류: {e}")
        
        return base64_images
    
    @staticmethod
    def is_image_data(data: str) -> bool:
        """문자열이 이미지 데이터인지 간단 검증"""
        try:
            # base64 길이가 너무 짧으면 이미지가 아닐 가능성 높음
            if len(data) < 100:
                return False
                
            # base64 디코딩 테스트
            base64.b64decode(data[:100])  # 앞 100자만 테스트
            return True
        except Exception:
            return False