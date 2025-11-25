from mitmproxy import http
from mitmproxy import ctx
import time

TARGET_PATH = "/backend/api/file"
TARGET_HOST = "chatgpt.com"

class Interceptor:
    def request(self, flow: http.HTTPFlow):

        host = flow.request.host
        path = flow.request.path
        method = flow.request.method

        # POST + host == chatgpt.com + path match
        if method == "POST" and TARGET_PATH in path and TARGET_HOST in host:
            ctx.log.info("=== File Upload Intercepted ===")
            ctx.log.info(f"Host: {host}")
            ctx.log.info(f"URL: {flow.request.url}")
            ctx.log.info(f"Headers: {flow.request.headers}")
            ctx.log.info(f"Raw Body Size: {len(flow.request.content)} bytes")

            try:
                ctx.log.info("Body (UTF-8):")
                ctx.log.info(flow.request.content.decode("utf-8", errors="ignore"))
            except:
                pass

            ctx.log.info(">> Holding request for 10 seconds...")
            time.sleep(10)
            ctx.log.info(">> Release request and forwarding.")

    def response(self, flow: http.HTTPFlow):

        host = flow.request.host
        path = flow.request.path

        if flow.request.method == "POST" and TARGET_PATH in path and TARGET_HOST in host:
            ctx.log.info("=== Upload Response ===")
            ctx.log.info(f"Status: {flow.response.status_code}")
            if flow.response.text:
                ctx.log.info(flow.response.text[:500])


addons = [Interceptor()]
