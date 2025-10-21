from pathlib import Path
import json

log = Path.home() / '.llm_proxy' / 'debugging.json'
data = json.loads(log.read_text(encoding='utf-8'))

print(f"Total entries: {len(data)}\n")

for idx, entry in enumerate(data):
    if 'oaiusercontent' in entry.get('host', '') and entry.get('method') == 'PUT' and entry.get('type') == 'http_request':
        print(f"=== Found at Index: {idx} ===")
        print(f"Array position: data[{idx}]")
        print(f"Host: {entry['host']}")
        print(f"Content-Type: {entry.get('request_headers', {}).get('content-type')}")
        print(f"Content-Size: {entry.get('content_size')} bytes")
        print(f"Body length: {len(entry.get('request_body', ''))} chars")
        print(f"Time: {entry['time']}")
        print(f"\nData location: {log}")
        print(f"Access in Python: data[{idx}]['request_body']")
        print()
