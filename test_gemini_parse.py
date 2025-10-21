from urllib.parse import unquote_plus
import json

# 예시 1: 사용자 프롬프트
raw1 = """f.req=%5Bnull%2C%22%5B%5B%5C%22%EC%95%88%EB%85%95%20%EC%A0%9C%EB%AF%B8%EB%82%98%EC%9D%B4%EC%95%BC%5C%22%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2C0%5D%2C%5B%5C%22ko%5C%22%5D%2C%5B%5C%22%5C%22%2C%5C%22%5C%22%2C%5C%22%5C%22%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%5C%22%5C%22%5D%2C%5C%22!BQalBl7NAAa-BNTXngRCns3oUQ_UNOw7ADQBEArZ1GMFEOBNP9VhJ7eBy8XSO1ByWirPjpKrYO2SKss_P7sEneWffp7QC4C8x6MxpyvBAgAAAMlSAAAAC2gBB34AQagTkh3FlQk21CoSS_HdOyPHUAOsThuCTWSTHM4vusLQuJ695j7wNtAXC1HCFNWzVyh3rWAPrwn4oytI4l9p1QkzmQN7Sszh1UWt0bs3Dal4nyhn9sX6LrirKIqrHx5dnlvDHtzS3-o72W9sFadUz7560Y6xpi51YJg8icsVCAfw2Z-b1053dS9ygXH6zeGO-XAvWVaYsgxk_OR39FpVMb93o1im59ss_fcj9D194cAEn-Siqm07ccAgx8n-a86TyJC3bo4c2AsrXRA862yS6eR3WK6xE7cpRkncsAcZIbQX5fR0-LEbXVfTL9RiwSTjVDTGhdKk0KxV3qytvU6oI_p89lZVbFfSpX_K1tW0zpqOmqKJiwHg_Kq4NrRB-xE9KcdNoH7FJvzQRaSPFSWSYvxVR1I02nBzVEU2a9yTFt8GIw8OhL0VemxeSsBpD7XZhiFu8bzt_cxfv22h5HSLigSewcmT1pD3Vsf1WFa_ngLOu8LlO8S8n20acy3VVVfUYPWd8gQfgE3y83I4cq-nGZ1wkwNgqFpvAdMYNYr_Or-L--kZur1a7cdlLbSgK5EImCbasUyL5UBqTyb9G"""

# 예시 2: 설정 요청 (쓰레기)
raw2 = """f.req=%5B%5B%5B%22ESY5D%22%2C%22%5B%5B%5B%5C%22bard_activity_enabled%5C%22%5D%5D%5D%22%2Cnull%2C%22generic%22%5D%5D%5D"""

def analyze_f_req(raw, label):
    print(f"\n{'='*80}")
    print(f"{label}")
    print('='*80)

    try:
        # f.req= 제거
        f_req = raw.split('f.req=')[1].split('&')[0]

        # URL 디코딩
        decoded = unquote_plus(f_req)
        print('Step 1: URL Decoded')
        print(decoded)
        print()

        # JSON 파싱 (outer)
        outer = json.loads(decoded)
        print('Step 2: Outer Array')
        print(f'  Length: {len(outer)}')
        print(f'  outer[0]: {outer[0]}')
        print(f'  outer type: {type(outer)}')
        print()

        # 구조 체크
        if outer[0] is None and len(outer) >= 2:
            print("✅ outer[0] == null 패턴 발견!")
            inner_str = outer[1]
            print(f'  outer[1] type: {type(inner_str)}')

            if isinstance(inner_str, str):
                inner = json.loads(inner_str)
                print('Step 3: Inner Array')
                print(f'  Length: {len(inner)}')
                for i, item in enumerate(inner):
                    print(f'  inner[{i}]: {item}')
                    if i == 0 and isinstance(item, list) and len(item) > 0:
                        print(f'    ⭐ inner[0][0]: {item[0]} (프롬프트 후보)')
        else:
            print("❌ outer[0]이 null이 아님 -> 사용자 프롬프트 아님!")

    except Exception as e:
        print(f'❌ Error: {e}')

# 두 패턴 비교
analyze_f_req(raw1, "예시 1: 사용자 프롬프트")
analyze_f_req(raw2, "예시 2: 설정 요청 (쓰레기)")
