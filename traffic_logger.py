#!/usr/bin/env python3
"""
트래픽 로거 - LLM API 트래픽 감지 및 로깅 설정 관리
"""
from pathlib import Path
from typing import Set
import json

print("traffic_logger.py 시작")

class TrafficLogger:
    """LLM 트래픽 로깅 설정을 담당하는 클래스"""
    
    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.json_log_file = app_dir / "llm_api_requests.json"
        self.config_file = app_dir / "llm_hosts_config.json"
        
        # --- 로깅할 웹 기반 LLM 서비스 호스트 목록 ---
        self.WEB_HOSTS: Set[str] = {
            "chatgpt.com",
            "claude.ai",
            "gemini.google.com"
        }
        
        # --- 로깅할 API 및 앱 기반 LLM 서비스 호스트 목록 ---                                
        self.API_HOSTS: Set[str] = {
            "api.openai.com", 
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com", 
            "api.groq.com",
            "api.cohere.ai",
            "api.deepseek.com",
            "api2.cursor.sh", 
            "api3.cursor.sh", 
            "repo42.cursor.sh", 
            "localhost", 
            "127.0.0.1"
            "metrics.cursor.sh"
        }
        
        # 전체 LLM 호스트 목록 (웹 + API)
        self.LLM_HOSTS = self.WEB_HOSTS | self.API_HOSTS
        
        # 설정 파일에서 호스트 목록 로드
        self.load_hosts_config()

    def get_script_path(self) -> Path:
        """mitmproxy 스크립트 파일 경로 반환"""
        script_path = Path(__file__).parent / "api_main.py"
        
        # 스크립트 파일이 존재하는지 확인
        if not script_path.exists():
            print(f"[ERROR] mitmproxy 스크립트 파일을 찾을 수 없습니다: {script_path}")
            print("[INFO] api_main.py 파일이 같은 디렉터리에 있는지 확인하세요.")
        else:
            print(f"[INFO] mitmproxy 스크립트: {script_path}")
            
        return script_path

    def load_hosts_config(self):
        """설정 파일에서 LLM 호스트 목록을 로드"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    loaded_hosts = set(config.get('llm_hosts', []))
                    if loaded_hosts:
                        self.LLM_HOSTS = loaded_hosts
                        print(f"[CONFIG] 설정에서 {len(loaded_hosts)}개 호스트 로드")
                    else:
                        # 빈 설정이면 기본값 저장
                        self.save_hosts_config()
            except Exception as e:
                print(f"[WARN] 설정 파일 로드 실패, 기본값 사용: {e}")
                self.save_hosts_config()
        else:
            # 설정 파일이 없으면 기본값으로 생성
            print(f"[INFO] 기본 설정 파일 생성: {self.config_file}")
            self.save_hosts_config()

    def save_hosts_config(self):
        """현재 LLM 호스트 목록을 설정 파일에 저장"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            config = {'llm_hosts': sorted(list(self.LLM_HOSTS))}
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f"[CONFIG] 호스트 설정 저장 완료: {len(self.LLM_HOSTS)}개")
        except Exception as e:
            print(f"[ERROR] 설정 파일 저장 실패: {e}")

    def add_llm_host(self, host: str):
        """새로운 LLM 호스트를 추가"""
        self.LLM_HOSTS.add(host)
        self.save_hosts_config()
        print(f"[INFO] 호스트 추가됨: {host}")
        
    def remove_llm_host(self, host: str):
        """LLM 호스트를 제거"""
        self.LLM_HOSTS.discard(host)
        self.save_hosts_config()
        print(f"[INFO] 호스트 제거됨: {host}")
        
    def get_llm_hosts(self) -> Set[str]:
        """현재 등록된 LLM 호스트 목록 반환"""
        return self.LLM_HOSTS.copy()
    
    def is_llm_host(self, host: str) -> bool:
        """주어진 호스트가 LLM 서비스 호스트인지 확인"""
        return any(llm_host in host for llm_host in self.LLM_HOSTS)
    
    def print_status(self):
        """현재 설정 상태를 출력"""
        print(f"\n=== TrafficLogger 설정 현황 ===")
        print(f"로그 파일: {self.json_log_file}")
        print(f"설정 파일: {self.config_file}")
        print(f"스크립트 파일: {self.get_script_path()}")
        print(f"모니터링 호스트 ({len(self.LLM_HOSTS)}개):")
        for i, host in enumerate(sorted(self.LLM_HOSTS), 1):
            print(f"  {i:2d}. {host}")
        print(f"===========================\n")

# 직접 실행 시 테스트
if __name__ == "__main__":
    from pathlib import Path
    
    app_dir = Path.home() / ".llm_proxy"
    logger = TrafficLogger(app_dir)
    logger.print_status()
    
    # 테스트용 임시 로그 파일 생성
    # test_log = {
    #     "time": "2024-01-01T12:00:00",
    #     "host": "test.example.com",
    #     "direction": "test",
    #     "message": "TrafficLogger 테스트 엔트리"
    # }
    
    try:
        import json
        with open(logger.json_log_file, "w", encoding="utf-8") as f:
            json.dump([test_log], f, ensure_ascii=False, indent=2)
        print(f"[TEST] 테스트 로그 파일이 생성되었습니다: {logger.json_log_file}")
    except Exception as e:
        print(f"[ERROR] 테스트 로그 생성 실패: {e}")