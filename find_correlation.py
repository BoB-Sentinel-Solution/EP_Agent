from pathlib import Path
import json
from datetime import datetime

log = Path.home() / '.llm_proxy' / 'debugging.json'
data = json.loads(log.read_text(encoding='utf-8'))

# PUT 요청 찾기
put_indices = [i for i, e in enumerate(data) if e.get('method') == 'PUT' and 'oaiusercontent' in e.get('host', '')]

if not put_indices:
    print("PUT 요청을 찾을 수 없습니다.")
    exit(1)

put_idx = put_indices[-1]
put_req = data[put_idx]

print('='*80)
print('=== PUT 요청 정보 ===')
print('='*80)
print(f"Index: {put_idx}")
print(f"Time: {put_req['time']}")
print(f"Host: {put_req['host']}")
print(f"Path: {put_req['path'][:80]}")

# File ID 추출
file_id = None
if '/files/' in put_req['path']:
    file_id = put_req['path'].split('/files/')[1].split('/')[0]
    print(f"File ID: {file_id}")

print('\n' + '='*80)
print('=== 전후 10개 요청 (시간순) ===')
print('='*80)

for i in range(max(0, put_idx-10), min(len(data), put_idx+11)):
    e = data[i]
    mark = '>>> PUT' if i == put_idx else '       '
    time_str = e.get('time', 'N/A')[:23]
    method = e.get('method', '?').ljust(4)
    host = e.get('host', '?').ljust(40)
    path = e.get('path', '')[:50]

    print(f"{mark} [{i:3d}] {time_str} | {method} {host} {path}")

# POST 요청 중 file_id가 포함된 것 찾기
print('\n' + '='*80)
print('=== File ID가 포함된 다른 요청 찾기 ===')
print('='*80)

if file_id:
    for i, e in enumerate(data):
        if i == put_idx:
            continue

        # path나 body에 file_id가 있는지 확인
        path = e.get('path', '')
        body = str(e.get('request_body', ''))

        if file_id in path or file_id in body:
            print(f"[{i}] {e.get('time', 'N/A')[:23]} | {e.get('method')} {e.get('host')} {path[:60]}")
else:
    print("File ID를 추출할 수 없습니다.")

print('\n' + '='*80)
print('=== 연관 정보 후보 ===')
print('='*80)
print("""
1. ✅ File ID (UUID)
   - PUT path: /files/{file_id}/...
   - POST body에 file_id 포함 가능성

2. ✅ 시간 차이 (Time Window)
   - PUT 이후 5초 이내 POST 요청

3. ⚠️ Cookie/Session
   - 같은 세션 ID

4. ⚠️ Conversation ID
   - POST body에 대화 ID 포함 가능성
""")
