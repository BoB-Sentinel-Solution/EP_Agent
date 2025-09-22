from flask import Flask, request, jsonify
import json
from datetime import datetime
import threading

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# 로그와 제어 규칙 저장
logs = []
control_rules = {}  # host별 제어 규칙
log_lock = threading.Lock()

@app.route('/control', methods=['POST'])
def control_request():
    """패킷 제어 요청 - mitmproxy에서 호출"""
    try:
        data = request.get_json()
        host = data.get('host', 'unknown')
        prompt = data.get('prompt', '')
        
        # 로그 저장
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'host': host,
            'prompt': prompt,
            'action': None  # 나중에 업데이트
        }
        
        with log_lock:
            logs.append(log_entry)
            if len(logs) > 1000:
                logs.pop(0)
        
        # 제어 규칙 확인
        rule = control_rules.get(host, control_rules.get('default', {}))
        
        # 기본 동작 결정
        action = rule.get('action', 'allow')  # allow, block, modify
        modified_prompt = prompt
        
        if action == 'block':
            result = {
                'action': 'block',
                'message': '차단된 요청'
            }
        elif action == 'modify':
            # 프롬프트 변조
            modified_prompt = rule.get('replacement', '[변조된 프롬프트]')
            result = {
                'action': 'modify',
                'modified_prompt': modified_prompt
            }
        else:  # allow
            result = {
                'action': 'allow'
            }
        
        # 로그에 액션 기록
        log_entry['action'] = action
        if action == 'modify':
            log_entry['modified_prompt'] = modified_prompt
        
        print(f"🔍 [{host}] {prompt[:50]}... -> {action.upper()}")
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ 제어 에러: {str(e)}")
        return jsonify({'action': 'allow', 'error': str(e)}), 500

@app.route('/rules', methods=['GET'])
def get_rules():
    """현재 제어 규칙 조회"""
    return jsonify(control_rules)

@app.route('/rules/<host>', methods=['POST'])
def set_rule(host):
    """특정 호스트의 제어 규칙 설정"""
    try:
        rule_data = request.get_json()
        control_rules[host] = rule_data
        print(f"🔧 규칙 설정: {host} -> {rule_data}")
        return jsonify({'status': 'success', 'host': host, 'rule': rule_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/rules/<host>', methods=['DELETE']) 
def delete_rule(host):
    """특정 호스트의 제어 규칙 삭제"""
    if host in control_rules:
        del control_rules[host]
        return jsonify({'status': 'success', 'message': f'{host} 규칙 삭제됨'})
    else:
        return jsonify({'status': 'error', 'message': '규칙이 존재하지 않음'}), 404

@app.route('/logs', methods=['GET'])
def get_logs():
    """로그 조회"""
    with log_lock:
        data = {
            'total': len(logs),
            'logs': logs[-50:]
        }
        response = app.response_class(
            response=json.dumps(data, ensure_ascii=False, indent=2),
            status=200,
            mimetype='application/json; charset=utf-8'
        )
        return response

@app.route('/dashboard', methods=['GET'])
def dashboard():
    """실시간 대시보드"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM 패킷 제어 대시보드</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; margin: 20px; background: #1a1a1a; color: #fff; }
            .container { display: flex; gap: 20px; }
            .panel { flex: 1; border: 1px solid #333; padding: 15px; }
            .log-entry { margin: 5px 0; padding: 8px; border-left: 3px solid #00ff00; }
            .blocked { border-left-color: #ff0000; }
            .modified { border-left-color: #ffff00; }
            .allowed { border-left-color: #00ff00; }
            input, select, button { padding: 8px; margin: 5px; }
            button { background: #007acc; color: white; border: none; cursor: pointer; }
            button:hover { background: #005999; }
        </style>
    </head>
    <body>
        <h1>🛡️ LLM 패킷 제어 대시보드</h1>
        
        <div class="container">
            <div class="panel">
                <h3>📋 실시간 로그</h3>
                <div id="logs" style="height: 400px; overflow-y: scroll;"></div>
            </div>
            
            <div class="panel">
                <h3>⚙️ 제어 규칙</h3>
                <div>
                    <input type="text" id="host" placeholder="호스트 (예: chatgpt.com)">
                    <select id="action">
                        <option value="allow">허용</option>
                        <option value="block">차단</option>
                        <option value="modify">변조</option>
                    </select>
                    <input type="text" id="replacement" placeholder="변조할 텍스트 (변조 시)">
                    <button onclick="setRule()">규칙 설정</button>
                </div>
                <div id="rules"></div>
            </div>
        </div>
        
        <script>
            function fetchLogs() {
                fetch('/logs')
                    .then(res => res.json())
                    .then(data => {
                        const container = document.getElementById('logs');
                        container.innerHTML = '';
                        data.logs.forEach(log => {
                            const div = document.createElement('div');
                            div.className = `log-entry ${log.action || 'allowed'}`;
                            div.innerHTML = `
                                <div><strong>[${log.host}]</strong> ${log.action?.toUpperCase() || 'ALLOWED'}</div>
                                <div>${log.prompt}</div>
                                ${log.modified_prompt ? `<div style="color: #ffff00;">→ ${log.modified_prompt}</div>` : ''}
                            `;
                            container.appendChild(div);
                        });
                        container.scrollTop = container.scrollHeight;
                    });
            }
            
            function fetchRules() {
                fetch('/rules')
                    .then(res => res.json())
                    .then(rules => {
                        const container = document.getElementById('rules');
                        container.innerHTML = '<h4>현재 규칙:</h4>';
                        Object.entries(rules).forEach(([host, rule]) => {
                            const div = document.createElement('div');
                            div.innerHTML = `
                                <strong>${host}</strong>: ${rule.action} 
                                ${rule.replacement ? `(→ ${rule.replacement})` : ''}
                                <button onclick="deleteRule('${host}')" style="background: #dc3545;">삭제</button>
                            `;
                            container.appendChild(div);
                        });
                    });
            }
            
            function setRule() {
                const host = document.getElementById('host').value;
                const action = document.getElementById('action').value;
                const replacement = document.getElementById('replacement').value;
                
                const rule = { action };
                if (action === 'modify') rule.replacement = replacement;
                
                fetch(`/rules/${host}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(rule)
                }).then(() => {
                    fetchRules();
                    document.getElementById('host').value = '';
                    document.getElementById('replacement').value = '';
                });
            }
            
            function deleteRule(host) {
                fetch(`/rules/${host}`, { method: 'DELETE' })
                    .then(() => fetchRules());
            }
            
            setInterval(fetchLogs, 2000);
            setInterval(fetchRules, 5000);
            window.onload = () => { fetchLogs(); fetchRules(); };
        </script>
    </body>
    </html>
    '''
    return html

if __name__ == '__main__':
    print("🛡️ LLM 패킷 제어 서버 시작!")
    print("📡 대시보드: http://127.0.0.1:8080/dashboard")
    print("=" * 50)
    
    app.run(host='127.0.0.1', port=8080, debug=True, threaded=True)