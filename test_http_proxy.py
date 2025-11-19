#!/usr/bin/env python3
"""
HTTP 프록시 기능 테스트 스크립트
"""
import asyncio
import socket
from datetime import datetime

async def test_http_proxy():
    """HTTP 프록시 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] HTTP 프록시 테스트 시작")

    # 프록시 서버가 실행 중인지 확인
    proxy_host = '127.0.0.1'
    proxy_port = 8081  # 기본 프록시 포트

    try:
        # 소켓 연결 테스트
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((proxy_host, proxy_port))
            if result != 0:
                print(f"[ERROR] 프록시 서버 ({proxy_host}:{proxy_port})에 연결할 수 없습니다.")
                print("먼저 main.py를 실행하여 프록시 서버를 시작하세요.")
                return False

        print(f"[OK] 프록시 서버 연결 성공: {proxy_host}:{proxy_port}")

        # HTTP 요청 테스트
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        try:
            # HTTP GET 요청 (절대 URL 방식)
            http_request = (
                "GET http://httpbin.org/ip HTTP/1.1\r\n"
                "Host: httpbin.org\r\n"
                "User-Agent: SentinelProxy-Test/1.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            print(f"[SEND] HTTP 요청 전송:")
            print(http_request.strip())

            # 요청 전송
            writer.write(http_request.encode())
            await writer.drain()

            # 응답 읽기
            response_data = b""
            while True:
                chunk = await reader.read(1024)
                if not chunk:
                    break
                response_data += chunk

            # 응답 출력
            response_text = response_data.decode('utf-8', errors='ignore')
            print(f"\n[RECV] HTTP 응답 수신:")
            print("-" * 50)
            print(response_text[:500])  # 처음 500자만 출력
            if len(response_text) > 500:
                print("...")
            print("-" * 50)

            if "HTTP/1.1 200" in response_text or "HTTP/1.0 200" in response_text:
                print("[SUCCESS] HTTP 프록시 테스트 성공!")
                return True
            else:
                print("[WARNING] HTTP 응답이 예상과 다릅니다.")
                return False

        finally:
            writer.close()
            await writer.wait_closed()

    except Exception as e:
        print(f"[ERROR] HTTP 프록시 테스트 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_llm_host_detection():
    """LLM 호스트 감지 테스트"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] LLM 호스트 감지 테스트 시작")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        try:
            # OpenAI API 호스트로 테스트 (HTTP)
            http_request = (
                "GET http://api.openai.com/v1/models HTTP/1.1\r\n"
                "Host: api.openai.com\r\n"
                "User-Agent: SentinelProxy-Test/1.0\r\n"
                "Authorization: Bearer test-key\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            print(f"[SEND] LLM 호스트 요청 전송 (api.openai.com):")
            print(http_request.strip())

            # 요청 전송
            writer.write(http_request.encode())
            await writer.drain()

            # 짧은 응답만 확인 (인증 오류여도 연결은 성공)
            response_chunk = await reader.read(512)
            response_text = response_chunk.decode('utf-8', errors='ignore')

            print(f"\n[RECV] LLM 호스트 응답:")
            print("-" * 30)
            print(response_text[:200])
            print("-" * 30)

            if "HTTP/1.1" in response_text:
                print("[SUCCESS] LLM 호스트 라우팅 성공!")
                return True
            else:
                print("[WARNING] LLM 호스트 응답 확인 필요")
                return False

        finally:
            writer.close()
            await writer.wait_closed()

    except Exception as e:
        print(f"[ERROR] LLM 호스트 테스트 실패: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Sentinel Proxy HTTP 기능 테스트")
    print("=" * 60)

    async def run_tests():
        # 기본 HTTP 프록시 테스트
        test1_result = await test_http_proxy()

        # LLM 호스트 감지 테스트
        test2_result = await test_llm_host_detection()

        # 결과 요약
        print("\n" + "=" * 60)
        print("테스트 결과 요약:")
        print(f"  일반 HTTP 프록시: {'✓ 성공' if test1_result else '✗ 실패'}")
        print(f"  LLM 호스트 감지:  {'✓ 성공' if test2_result else '✗ 실패'}")
        print("=" * 60)

        if test1_result and test2_result:
            print("\n🎉 모든 테스트가 성공했습니다!")
            print("이제 HTTP 기반 애플리케이션들도 프록시를 통해 보안 감시가 가능합니다.")
        else:
            print("\n⚠️ 일부 테스트가 실패했습니다. 프록시 서버 상태를 확인하세요.")

    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        print("\n\n테스트가 중단되었습니다.")
    except Exception as e:
        print(f"\n테스트 실행 중 오류: {e}")