# proxy/interceptor.py
import base64, json, os, time, re, asyncio
from datetime import datetime, timezone, timedelta
import httpx
from mitmproxy import http, ctx

INSPECTOR_URL = os.getenv("INSPECTOR_URL", "http://127.0.0.1:8000/inspect")
INTERFACE = os.getenv("INTERFACE", "llm")  # or "mcp"
CONNECT_TIMEOUT = float(os.getenv("INSPECT_CONNECT_TIMEOUT", "2.0"))
READ_TIMEOUT = float(os.getenv("INSPECT_READ_TIMEOUT", "4.0"))
TOTAL_TIMEOUT = float(os.getenv("INSPECT_TOTAL_TIMEOUT", "6.0"))
FAIL_OPEN = os.getenv("INSPECT_FAIL_OPEN", "true").lower() == "true"
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "1048576"))  # 1MB 요청 본문 상한
CONC_LIMIT = int(os.getenv("INSPECT_CONCURRENCY", "32"))

# 민감헤더 레드랙션(에이전트→서버 구간에서만)
SENSITIVE_HDRS = re.compile(r"^(authorization|cookie|x-api-key|x-goog-api-key|proxy-authorization|set-cookie)$", re.I)

_semaphore = asyncio.Semaphore(CONC_LIMIT)

def _now_kst():
    return datetime.now(timezone(timedelta(hours=9))).isoformat()

def _redact_headers(headers: http.Headers) -> dict:
    out = {}
    for k, v in headers.items(multi=True):
        if SENSITIVE_HDRS.match(k):
            if len(v) > 12:
                out[k] = v[:4] + "****" + v[-4:]
            else:
                out[k] = "***"
        else:
            out[k] = v
    return out

async def _call_inspector(payload: dict) -> dict:
    timeout = httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=READ_TIMEOUT, pool=2*READ_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as cli:
        r = await cli.post(INSPECTOR_URL, json=payload)
        r.raise_for_status()
        return r.json()

async def _inspect_request(flow: http.HTTPFlow):
    # 요청 본문 제한
    body = flow.request.raw_content or b""
    if body and len(body) > MAX_BODY_BYTES:
        # 과대 본문은 샘플만 보냄(앞/뒤 512B)
        head, tail = body[:512], body[-512:]
        body_b64 = base64.b64encode(head + b"...TRUNCATED..." + tail).decode()
    else:
        body_b64 = base64.b64encode(body).decode() if body else None

    payload = {
        "time": _now_kst(),
        "interface": INTERFACE,
        "direction": "request",
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": flow.request.path.split("?", 1)[0],
        "query": flow.request.query or "",
        "headers": _redact_headers(flow.request.headers),
        "body_b64": body_b64,
        "client_ip": flow.client_conn.address[0] if flow.client_conn.address else None,
        "server_ip": None,
        "tags": _infer_tags(flow),
    }

    # 서버에 동기 질의(홀드)
    try:
        async with _semaphore:
            resp = await _call_inspector(payload)
    except Exception as e:
        ctx.log.warn(f"[inspector] error: {e!r} | fail_open={FAIL_OPEN}")
        if FAIL_OPEN:
            return  # 그대로 통과
        # fail-close면 차단
        _block(flow, reason="inspector_error")
        return

    decision = resp.get("decision", "allow")
    reason = resp.get("reason", "")
    if decision == "block":
        _block(flow, reason or "blocked_by_policy", rules_hit=resp.get("rules_hit", []))
    elif decision == "mask":
        masked_b64 = resp.get("masked_body_b64")
        if masked_b64 is not None:
            try:
                new_body = base64.b64decode(masked_b64)
                flow.request.raw_content = new_body
                # 길이 재계산
                if "content-length" in flow.request.headers:
                    flow.request.headers["content-length"] = str(len(new_body))
            except Exception as e:
                ctx.log.warn(f"[inspector] mask decode error: {e!r}")
                if not FAIL_OPEN:
                    _block(flow, reason="mask_decode_error")
    else:
        # allow: 그대로 진행
        pass

def _block(flow: http.HTTPFlow, reason: str, rules_hit=None):
    rules_hit = rules_hit or []
    body = (f"""
    <html><head><meta charset="utf-8"><title>Blocked</title></head>
    <body style="font-family:system-ui">
      <h2>요청이 차단되었습니다</h2>
      <p><b>사유:</b> {reason}</p>
      <p><b>규칙:</b> {", ".join(rules_hit)}</p>
      <hr>
      <small>Sentinel Solution · EP Agent</small>
    </body></html>
    """).encode("utf-8")
    flow.response = http.Response.make(
        403, body, {"Content-Type": "text/html; charset=utf-8"}
    )

def _infer_tags(flow: http.HTTPFlow):
    h = flow.request.headers.get("host", flow.request.host) or ""
    path = flow.request.path
    tags = []
    # 간단한 벤더 태깅
    if "openai" in h: tags += ["openai"]
    if "anthropic" in h or "claude" in h: tags += ["anthropic"]
    if "googleapis" in h or "gemini" in h or "generativelanguage" in h: tags += ["gemini"]
    if "groq" in h: tags += ["groq"]
    if "deepseek" in h: tags += ["deepseek"]
    # API 타입 추정
    if "/v1/chat/completions" in path or "/messages" in path:
        tags += ["chat"]
    return tags

class Interceptor:
    def __init__(self):
        ctx.log.info(f"[interceptor] up. inspector={INSPECTOR_URL} fail_open={FAIL_OPEN}")

    def request(self, flow: http.HTTPFlow):
        # HTTPS만 처리(원하면 HTTP도 포함 가능)
        if flow.request.scheme not in ("https", "http"):
            return
        # 비LLM 대상은 패스하고 싶다면 여기서 host 화이트리스트 검사
        asyncio.get_event_loop().run_until_complete(_inspect_request(flow))

addons = [Interceptor()]
