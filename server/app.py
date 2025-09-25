# server/app.py
import base64, json, re, hashlib, os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="Sentinel Inspector")

# 간단 룰(데모용): 카드번호 Luhn, 이메일, 한국 휴대폰, AWS키, JWT
CARD = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{{2,}}\b')
PHONE = re.compile(r'\b01[0-9]-?\d{{3,4}}-?\d{{4}}\b')
AWS = re.compile(r'\bAKIA[0-9A-Z]{{16}}\b')
JWT = re.compile(r'\beyJ[\w-]+\.[\w-]+\.[\w-]+\b')

def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(digits) <= 19): return False
    checksum = 0; parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        y = d*2 if (i % 2 == parity) else d
        checksum += y-9 if y>9 else y
    return (checksum + digits[-1]) % 10 == 0

def redact_text(t: str, rules_hit: List[str]) -> str:
    def mask_card(m):
        raw = m.group(0)
        if luhn_ok(raw):
            rules_hit.append("card")
            return re.sub(r'\d(?=\d{4}\b)', '*', raw)
        return raw
    t = CARD.sub(mask_card, t)
    t = EMAIL.sub(lambda m: (rules_hit.append("email") or (m.group(0)[0] + "***@" + m.group(0).split("@")[1])), t)
    t = PHONE.sub(lambda m: (rules_hit.append("phone") or (m.group(0)[:3] + "-****-" + m.group(0)[-4:])), t)
    t = AWS.sub(lambda m: (rules_hit.append("aws_key") or (m.group(0)[:4] + "****" + m.group(0)[-4:])), t)
    t = JWT.sub(lambda m: (rules_hit.append("jwt") or (m.group(0)[:4] + "****" + m.group(0)[-4:])), t)
    return t

class InspectIn(BaseModel):
    time: str
    interface: str
    direction: str
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    headers: dict
    body_b64: Optional[str] = None
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    tags: Optional[List[str]] = []

@app.post("/inspect")
async def inspect(inp: InspectIn, req: Request):
    # 기본 정책: 감지되면 mask, 특정 규칙 hit 많으면 block (데모)
    rules_hit: List[str] = []
    body = base64.b64decode(inp.body_b64) if inp.body_b64 else b""
    text = ""
    # JSON이면 텍스트화
    if body:
        try:
            # 원문 JSON을 마스킹하기 위해 문자열로 처리 후 다시 JSON 파싱 시도
            text = body.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

    masked_text = redact_text(text, rules_hit) if text else ""
    decision = "allow"
    masked_b64 = None

    if rules_hit:
        # 간단 정책: 룰 맞으면 mask
        decision = "mask"
        masked_b64 = base64.b64encode(masked_text.encode("utf-8")).decode()

        # 예: 특정 고위험 규칙 다수 적중 시 차단
        if sum(1 for r in rules_hit if r in ("card","aws_key","jwt")) >= 2:
            decision = "block"
            masked_b64 = None

    return JSONResponse({
        "decision": decision,
        "reason": "clean" if not rules_hit else "pii_or_secret_detected",
        "masked_body_b64": masked_b64,
        "redactions": list(set(rules_hit)),
        "rules_hit": rules_hit,
        "ttl_ms": 0
    })
