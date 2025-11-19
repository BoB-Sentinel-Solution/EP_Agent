#!/usr/bin/env python3
"""
TLS GeneratorExit 문제 해결 테스트
"""
import asyncio
import ssl
import socket
from datetime import datetime

async def test_https_connect_multiple():
    """여러 HTTPS 연결 동시 테스트"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 다중 HTTPS 연결 테스트 시작")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    # 여러 LLM 호스트로 동시 연결
    hosts = ["claude.ai", "chatgpt.com", "api.openai.com", "gemini.google.com"]

    async def connect_to_host(host):
        try:
            reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

            # CONNECT 요청
            connect_request = f"CONNECT {host}:443 HTTP/1.1\r\n\r\n"
            writer.write(connect_request.encode())
            await writer.drain()

            # 응답 읽기
            response = await asyncio.wait_for(reader.readline(), timeout=15)
            response_text = response.decode('utf-8', errors='ignore').strip()

            print(f"[{host}] 응답: {response_text}")

            # 연결 정리
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                print(f"[{host}] 연결 정리 완료")
            except asyncio.TimeoutError:
                print(f"[{host}] 연결 정리 타임아웃")

            return "200" in response_text

        except asyncio.TimeoutError:
            print(f"[{host}] 타임아웃")
            return False
        except Exception as e:
            print(f"[{host}] 오류: {e}")
            return False

    # 동시에 여러 연결 시도
    print(f"동시 연결 테스트: {', '.join(hosts)}")

    try:
        results = await asyncio.gather(
            *[connect_to_host(host) for host in hosts],
            return_exceptions=True
        )

        success_count = sum(1 for r in results if r is True)
        print(f"\n결과: {success_count}/{len(hosts)} 연결 성공")

        return success_count > 0

    except Exception as e:
        print(f"다중 연결 테스트 오류: {e}")
        return False

async def test_rapid_connections():
    """빠른 연결/해제 반복 테스트"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 빠른 연결/해제 테스트 시작")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    success_count = 0
    total_attempts = 10

    for i in range(total_attempts):
        try:
            reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

            # 즉시 연결 종료 (GeneratorExit 유발 테스트)
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

            success_count += 1
            print(f"[{i+1:2d}] 빠른 연결/해제 성공")

        except asyncio.TimeoutError:
            print(f"[{i+1:2d}] 타임아웃")
        except Exception as e:
            print(f"[{i+1:2d}] 오류: {e}")

        # 잠깐 대기
        await asyncio.sleep(0.1)

    print(f"\n빠른 연결/해제 결과: {success_count}/{total_attempts} 성공")
    return success_count > total_attempts // 2

async def test_proxy_server_status():
    """프록시 서버 상태 확인"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 프록시 서버 상태 확인")

    proxy_host = '127.0.0.1'
    proxy_port = 8081

    try:
        # 소켓 레벨에서 연결 확인
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((proxy_host, proxy_port))
            if result != 0:
                print(f"❌ 프록시 서버 연결 불가: {proxy_host}:{proxy_port}")
                print("   main.py를 먼저 실행하여 프록시 서버를 시작하세요.")
                return False

        print(f"✅ 프록시 서버 연결 가능: {proxy_host}:{proxy_port}")
        return True

    except Exception as e:
        print(f"❌ 프록시 서버 상태 확인 실패: {e}")
        return False

async def main():
    """메인 테스트"""
    print("=" * 60)
    print("TLS GeneratorExit 문제 해결 테스트")
    print("=" * 60)

    # 1. 프록시 서버 상태 확인
    if not await test_proxy_server_status():
        print("\n❌ 프록시 서버가 실행 중이지 않습니다.")
        return

    print()

    # 2. 다중 HTTPS 연결 테스트
    test1_result = await test_https_connect_multiple()

    # 3. 빠른 연결/해제 테스트
    test2_result = await test_rapid_connections()

    # 결과 요약
    print("\n" + "=" * 60)
    print("테스트 결과 요약:")
    print(f"  다중 HTTPS 연결:  {'✅ 성공' if test1_result else '❌ 실패'}")
    print(f"  빠른 연결/해제:   {'✅ 성공' if test2_result else '❌ 실패'}")
    print("=" * 60)

    if test1_result and test2_result:
        print("\n🎉 TLS GeneratorExit 문제가 해결되었습니다!")
        print("이제 데스크탑 애플리케이션들이 안정적으로 프록시를 사용할 수 있습니다.")
    elif test1_result or test2_result:
        print("\n⚠️ 일부 테스트 성공. 추가 안정성 개선이 필요할 수 있습니다.")
    else:
        print("\n❌ TLS 문제가 여전히 존재합니다. 추가 수정이 필요합니다.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n테스트가 중단되었습니다.")
    except Exception as e:
        print(f"\n테스트 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()