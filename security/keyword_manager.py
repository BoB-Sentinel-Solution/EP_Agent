import sqlite3
from pathlib import Path
from typing import List

class KeywordManager:
    """차단 키워드 관리 클래스"""
    
    def __init__(self, db_path: Path = None):
        if db_path is None:
            self.db_path = Path.home() / ".llm_proxy" / "keywords.db"
        else:
            self.db_path = db_path
            
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """데이터베이스 초기화 및 기본 키워드 설정"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS keywords (
                id INTEGER PRIMARY KEY,
                keyword TEXT UNIQUE NOT NULL
            )
            ''')
            
            # 기본 차단 키워드
            default_keywords = [
                "비밀번호", "패스워드", "password", 
                "주민등록번호", "주민번호", 
                "계좌번호", "계좌", 
                "기밀", "대외비", "철지",
                "신용카드", "카드번호"
            ]
            
            cursor.executemany(
                'INSERT OR IGNORE INTO keywords (keyword) VALUES (?)',
                [(k,) for k in default_keywords]
            )
            conn.commit()
    
    def get_keywords(self) -> List[str]:
        """차단 키워드 목록 반환"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT keyword FROM keywords')
            return [row[0] for row in cursor.fetchall()]
    
    def add_keyword(self, keyword: str) -> bool:
        """키워드 추가"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR IGNORE INTO keywords (keyword) VALUES (?)', (keyword,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False
    
    def remove_keyword(self, keyword: str) -> bool:
        """키워드 삭제"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM keywords WHERE keyword = ?', (keyword,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False