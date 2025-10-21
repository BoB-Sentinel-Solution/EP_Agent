from pathlib import Path
import json
import base64
from datetime import datetime

log = Path.home() / '.llm_proxy' / 'debugging.json'
data = json.loads(log.read_text(encoding='utf-8'))

put_req = [e for e in data if e.get('method') == 'PUT' and e.get('encoding') == 'base64'][-1]

print('='*60)
print('=== 현재 추출된 메타데이터 ===')
print('='*60)

# 1. 기본 정보
print(f'\n[기본 정보]')
print(f'Host: {put_req["host"]}')
print(f'Method: {put_req["method"]}')
print(f'Time: {put_req["time"]}')

# 2. 파일 정보
headers = put_req.get('request_headers', {})
content_type = headers.get('content-type', 'unknown')
print(f'\n[파일 정보]')
print(f'Content-Type: {content_type}')
print(f'File Extension: {content_type.split("/")[-1] if "/" in content_type else "unknown"}')
print(f'Content-Size: {put_req.get("content_size")} bytes ({put_req.get("content_size")/1024:.2f} KB)')
print(f'Encoding: {put_req.get("encoding")}')

# 3. URL 파싱
path = put_req.get('path', '')
print(f'\n[URL 정보]')
print(f'Full Path: {path[:100]}...')
if '/files/' in path:
    file_id = path.split('/files/')[1].split('/')[0]
    print(f'File ID: {file_id}')

# 4. 모든 헤더
print(f'\n[전체 헤더]')
for k, v in headers.items():
    print(f'  {k}: {v[:100] if len(str(v)) > 100 else v}')

# 5. PNG 시그니처 확인
print(f'\n[파일 검증]')
try:
    decoded = base64.b64decode(put_req['request_body'])
    png_sig = b'\x89PNG\r\n\x1a\n'
    is_valid_png = decoded.startswith(png_sig)
    print(f'PNG Signature Valid: {is_valid_png}')
    print(f'First 16 bytes: {" ".join(f"{b:02X}" for b in decoded[:16])}')
except Exception as e:
    print(f'Error: {e}')

print('\n' + '='*60)
print('=== 추가 추출 가능한 메타데이터 ===')
print('='*60)
print("""
1. ✅ Content-Type → 파일 확장자 (png, jpg, pdf 등)
2. ✅ Content-Size → 파일 크기
3. ✅ File ID (URL에서)
4. ⚠️  파일명 (헤더에 없음, ChatGPT가 안보냄)
5. ⚠️  업로드 시각 (타임스탬프만 있음)
6. ⚠️  이미지 해상도 (바이너리 파싱 필요)
7. ⚠️  EXIF 데이터 (PNG는 대부분 없음)
""")
