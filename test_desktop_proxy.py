#!/usr/bin/env python3
"""
데스크탑 애플리케이션 프록시 연결 테스트
"""
import asyncio
import socket
import time
from datetime import datetime

async def test_proxy_connection():
    """기본 프록시 연결 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 프록시 서버 연결 테스트")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        # 간단한 소켓 연결 테스트
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((proxy_host, proxy_port))
            if result != 0:
                print(f"❌ 프록시 서버에 연결할 수 없습니다: {proxy_host}:{proxy_port}")
                return False

        print(f"✅ 프록시 서버 연결 성공: {proxy_host}:{proxy_port}")
        return True

    except Exception as e:
        print(f"❌ 연결 테스트 실패: {e}")
        return False

async def test_https_connect():
    """HTTPS CONNECT 메소드 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] HTTPS CONNECT 테스트")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        try:
            # HTTPS CONNECT 요청 (Google로 테스트)
            connect_request = "CONNECT google.com:443 HTTP/1.1\r\n\r\n"
            writer.write(connect_request.encode())
            await writer.drain()

            # 응답 읽기 (200 Connection Established 대기)
            response = await asyncio.wait_for(reader.readline(), timeout=10)
            response_text = response.decode('utf-8', errors='ignore').strip()

            print(f"CONNECT 응답: {response_text}")

            if "200" in response_text and "Connection Established" in response_text:
                print("✅ HTTPS CONNECT 성공")
                return True
            else:
                print(f"❌ HTTPS CONNECT 실패: {response_text}")
                return False

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    except asyncio.TimeoutError:
        print("❌ HTTPS CONNECT 타임아웃")
        return False
    except Exception as e:
        print(f"❌ HTTPS CONNECT 오류: {e}")
        return False

async def test_http_request():
    """HTTP 요청 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] HTTP 요청 테스트")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        try:
            # HTTP GET 요청
            http_request = (
                "GET http://httpbin.org/ip HTTP/1.1\r\n"
                "Host: httpbin.org\r\n"
                "User-Agent: DesktopProxyTest/1.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            writer.write(http_request.encode())
            await writer.drain()

            # 응답 읽기
            response_data = b""
            start_time = time.time()
            while time.time() - start_time < 15:  # 15초 타임아웃
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=5)
                    if not chunk:
                        break
                    response_data += chunk
                except asyncio.TimeoutError:
                    break

            response_text = response_data.decode('utf-8', errors='ignore')

            if response_text:
                print(f"HTTP 응답 길이: {len(response_text)} bytes")
                first_line = response_text.split('\n')[0] if '\n' in response_text else response_text[:50]
                print(f"첫 줄: {first_line}")

                if "HTTP/1.1 200" in response_text or "HTTP/1.0 200" in response_text:
                    print("✅ HTTP 요청 성공")
                    return True
                else:
                    print(f"❌ HTTP 응답 오류: {first_line}")
                    return False
            else:
                print("❌ HTTP 응답 없음")
                return False

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    except Exception as e:
        print(f"❌ HTTP 요청 오류: {e}")
        return False

async def test_llm_host():
    """LLM 호스트 연결 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] LLM 호스트 연결 테스트")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        try:
            # OpenAI API 호스트로 CONNECT 요청
            connect_request = "CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n"
            writer.write(connect_request.encode())
            await writer.drain()

            # 응답 읽기
            response = await asyncio.wait_for(reader.readline(), timeout=10)
            response_text = response.decode('utf-8', errors='ignore').strip()

            print(f"LLM CONNECT 응답: {response_text}")

            if "200" in response_text:
                print("✅ LLM 호스트 연결 성공")
                return True
            else:
                print(f"❌ LLM 호스트 연결 실패: {response_text}")
                return False

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    except asyncio.TimeoutError:
        print("❌ LLM 호스트 연결 타임아웃")
        return False
    except Exception as e:
        print(f"❌ LLM 호스트 연결 오류: {e}")
        return False

async def main():
    """메인 테스트 실행"""
    print("=" * 60)
    print("Sentinel Proxy 데스크탑 연결 테스트")
    print("=" * 60)
    print()

    results = []

    # 1. 기본 연결 테스트
    results.append(await test_proxy_connection())
    print()

    # 2. HTTPS CONNECT 테스트
    results.append(await test_https_connect())
    print()

    # 3. HTTP 요청 테스트
    results.append(await test_http_request())
    print()

    # 4. LLM 호스트 테스트
    results.append(await test_llm_host())
    print()

    # 결과 요약
    print("=" * 60)
    print("테스트 결과 요약:")
    test_names = ["프록시 연결", "HTTPS CONNECT", "HTTP 요청", "LLM 호스트"]

    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✅ 성공" if result else "❌ 실패"
        print(f"  {i+1}. {name}: {status}")

    success_count = sum(results)
    total_count = len(results)

    print(f"\n전체 결과: {success_count}/{total_count} 성공")

    if success_count == total_count:
        print("\n🎉 모든 테스트 성공! 데스크탑 앱이 프록시를 통해 연결할 수 있습니다.")
    elif success_count > 0:
        print("\n⚠️ 일부 테스트 성공. 프록시는 작동하지만 일부 기능에 문제가 있을 수 있습니다.")
    else:
        print("\n❌ 모든 테스트 실패. 프록시 서버를 확인하세요.")

    print("=" * 60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n테스트가 중단되었습니다.")
    except Exception as e:
        print(f"\n테스트 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()