from fastapi import FastAPI, Request
import asyncio
from datetime import datetime

app = FastAPI()
logs = []

@app.post("/logs")
async def control(request: Request):
    data = await request.json()
    host = data.get("host")
    prompt = data.get("prompt")

    # 로그 기록
    log_entry = {"time": datetime.now().isoformat(), "host": host, "prompt": prompt}
    logs.append(log_entry)
    print(f"[FastAPI LOG] {host} - {prompt[:50]}...")

    # 3초 대기 시작
    print(f"{host} 요청 10초 홀딩 시작...")
    await asyncio.sleep(10)
    print(f"10초 홀딩 완료! 이제 응답 반환")

    # 응답 반환
    response_data = {"action": "allow", "message": "홀딩 테스트 완료"}
    print(f"mitmproxy로 응답 전송: {response_data}")


# @app.get("/logs")
# async def get_logs():
#     return logs