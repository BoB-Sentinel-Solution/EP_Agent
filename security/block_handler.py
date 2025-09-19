from mitmproxy import http

def create_block_response(keyword: str, context: str = "") -> http.Response:
    """차단 응답 HTML 생성 (JavaScript 팝업 포함)"""
    
    # 컨텍스트 길이 제한
    if len(context) > 100:
        context = context[:100] + "..."
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>전송 차단됨</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                text-align: center; 
                margin-top: 100px;
                background-color: #f5f5f5;
            }}
            .container {{
                background: white;
                margin: 0 auto;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 500px;
            }}
            .warning {{ 
                color: #d32f2f; 
                font-size: 24px; 
                margin-bottom: 20px;
                font-weight: bold;
            }}
            .info {{ 
                color: #666; 
                font-size: 16px; 
                line-height: 1.6;
            }}
            .keyword {{
                background: #ffebee;
                padding: 10px;
                border-radius: 5px;
                margin: 15px 0;
                border-left: 4px solid #d32f2f;
            }}
            .countdown {{
                color: #999;
                font-size: 14px;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="warning">🚨 전송이 차단되었습니다</div>
            <div class="info">
                <p>민감한 정보가 감지되어 AI 서비스로의 전송이 차단되었습니다.</p>
                <div class="keyword">
                    <strong>발견된 키워드:</strong> {keyword}
                </div>
                {f'<div class="keyword"><strong>감지된 문맥:</strong> {context}</div>' if context else ''}
                <div class="countdown">
                    <span id="countdown">3</span>초 후 이전 페이지로 이동합니다.
                </div>
            </div>
        </div>
        
        <script>
            // 즉시 알림 표시
            alert('⚠️ 민감정보가 감지되어 전송이 차단되었습니다.\\n\\n🔍 발견된 키워드: {keyword}\\n\\n보안을 위해 해당 내용을 제거 후 다시 시도해주세요.');
            
            // 카운트다운 및 페이지 이동
            let count = 3;
            const countdownElement = document.getElementById('countdown');
            
            const timer = setInterval(function() {{
                count--;
                countdownElement.textContent = count;
                
                if (count <= 0) {{
                    clearInterval(timer);
                    history.back();
                }}
            }}, 1000);
            
            // 페이지 클릭시 즉시 이동
            document.addEventListener('click', function() {{
                clearInterval(timer);
                history.back();
            }});
        </script>
    </body>
    </html>
    """
    
    return http.Response.make(
        status_code=200,
        content=html_content.encode('utf-8'),
        headers={"Content-Type": "text/html; charset=utf-8"}
    )


def create_json_block_response(keyword: str, context: str = "") -> http.Response:
    """API 요청용 JSON 차단 응답 (필요시 사용)"""
    
    response_data = {
        "error": "content_blocked",
        "message": f"민감한 키워드가 감지되어 요청이 차단되었습니다: {keyword}",
        "details": {
            "blocked_keyword": keyword,
            "context": context[:100] if context else "",
            "timestamp": "2024-01-01T00:00:00Z"  # 실제 구현시 datetime 사용
        }
    }
    
    return http.Response.make(
        status_code=403,
        content=str(response_data).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )