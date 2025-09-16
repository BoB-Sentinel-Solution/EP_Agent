#!/usr/bin/env python3
"""
비동기 OCR 관리자 - 백그라운드에서 OCR 처리 및 결과 관리
모든 환경(LLM/MCP/API)에서 재사용 가능
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Callable
import logging
from dataclasses import dataclass, asdict
import threading
import time

from .ocr_engine import OCREngine
from .file_watcher import FileWatcher


@dataclass
class OCRTask:
    """OCR 작업 정보"""
    id: int
    file_path: Path
    service: str  # chatgpt, claude, gemini, mcp, api 등
    timestamp: datetime
    priority: int = 1  # 1: 높음, 2: 보통, 3: 낮음


@dataclass
class OCRResult:
    """OCR 결과 정보"""
    id: int
    timestamp: str
    service: str
    original_file: str
    file_path: str
    ocr_result: str
    status: str  # pending, processing, completed, failed
    processing_time: float
    engine: str
    confidence: float
    error: Optional[str] = None


class AsyncOCRManager:
    """비동기 OCR 처리 관리자"""
    
    def __init__(self, 
                 watch_directory: Path,
                 result_directory: Path,
                 max_workers: int = 3,
                 auto_start: bool = True):
        """
        Args:
            watch_directory: 감시할 다운로드 폴더
            result_directory: 결과 저장 폴더 
            max_workers: 동시 OCR 작업 수
            auto_start: 자동 시작 여부
        """
        self.watch_directory = Path(watch_directory)
        self.result_directory = Path(result_directory)
        self.max_workers = max_workers
        
        # 디렉토리 생성
        self.watch_directory.mkdir(parents=True, exist_ok=True)
        self.result_directory.mkdir(parents=True, exist_ok=True)
        
        # OCR 엔진 초기화
        self.ocr_engine = OCREngine()
        
        # 작업 관리
        self.task_queue = asyncio.Queue()
        self.processing_tasks = {}  # task_id: asyncio.Task
        self.results = {}  # task_id: OCRResult
        self.task_id_counter = 1
        self.task_id_lock = threading.Lock()
        
        # 파일 감시자
        self.file_watcher = None
        
        # 이벤트 루프 관리
        self.loop = None
        self.is_running = False
        self.workers = []
        
        # 로깅
        self.logger = logging.getLogger(__name__)
        
        if auto_start:
            self.start()
    
    def _get_next_task_id(self) -> int:
        """스레드 안전한 ID 생성"""
        with self.task_id_lock:
            task_id = self.task_id_counter
            self.task_id_counter += 1
            return task_id
    
    def _extract_service_from_filename(self, filename: str) -> str:
        """파일명에서 서비스 추출 (예: 20250915_105600_claude_screenshot.png)"""
        filename_lower = filename.lower()
        
        # 서비스 키워드 매핑
        service_keywords = {
            'chatgpt': 'chatgpt',
            'openai': 'chatgpt', 
            'claude': 'claude',
            'anthropic': 'claude',
            'gemini': 'gemini',
            'google': 'gemini',
            'mcp': 'mcp',
            'api': 'api'
        }
        
        for keyword, service in service_keywords.items():
            if keyword in filename_lower:
                return service
        
        return 'unknown'  # 기본값
    
    def _create_service_directory(self, service: str) -> Path:
        """서비스별 결과 디렉토리 생성"""
        service_dir = self.result_directory / service
        service_dir.mkdir(parents=True, exist_ok=True)
        return service_dir
    
    async def add_ocr_task(self, file_path: Path, service: Optional[str] = None, priority: int = 1) -> int:
        """OCR 작업을 큐에 추가"""
        if not service:
            service = self._extract_service_from_filename(file_path.name)
        
        task_id = self._get_next_task_id()
        task = OCRTask(
            id=task_id,
            file_path=file_path,
            service=service,
            timestamp=datetime.now(),
            priority=priority
        )
        
        # 우선순위 큐에 추가 (숫자가 작을수록 높은 우선순위)
        await self.task_queue.put((priority, task))
        
        self.logger.info(f"OCR 작업 추가: {task_id} - {file_path.name} ({service})")
        return task_id
    
    async def _process_ocr_task(self, task: OCRTask) -> OCRResult:
        """개별 OCR 작업 처리"""
        self.logger.info(f"OCR 처리 시작: {task.id} - {task.file_path.name}")
        
        # OCR 실행
        ocr_result = await asyncio.get_event_loop().run_in_executor(
            None, 
            self.ocr_engine.extract_text, 
            task.file_path
        )
        
        # 결과 객체 생성
        result = OCRResult(
            id=task.id,
            timestamp=task.timestamp.isoformat(),
            service=task.service,
            original_file=task.file_path.name,
            file_path=str(task.file_path),
            ocr_result=ocr_result.get("text", ""),
            status="completed" if ocr_result.get("success") else "failed",
            processing_time=ocr_result.get("processing_time", 0.0),
            engine=ocr_result.get("engine", "unknown"),
            confidence=ocr_result.get("confidence", 0.0),
            error=ocr_result.get("error")
        )
        
        # 결과 저장
        await self._save_result(result)
        
        self.logger.info(f"OCR 처리 완료: {task.id} - {result.status}")
        return result
    
    async def _save_result(self, result: OCRResult):
        """OCR 결과를 JSON 파일로 저장"""
        try:
            # 서비스별 디렉토리 생성
            service_dir = self._create_service_directory(result.service)
            
            # 파일명 생성 (ID 기반)
            result_file = service_dir / f"ocr_result_{result.id:06d}.json"
            
            # JSON 저장
            result_data = asdict(result)
            
            def write_json():
                with open(result_file, 'w', encoding='utf-8') as f:
                    json.dump(result_data, f, ensure_ascii=False, indent=2)
            
            await asyncio.get_event_loop().run_in_executor(None, write_json)
            
            self.logger.info(f"결과 저장 완료: {result_file}")
            
        except Exception as e:
            self.logger.error(f"결과 저장 실패: {e}")
    
    async def _worker(self, worker_id: int):
        """OCR 작업 처리 워커"""
        self.logger.info(f"OCR 워커 {worker_id} 시작")
        
        while self.is_running:
            try:
                # 우선순위 큐에서 작업 가져오기 (타임아웃 1초)
                priority, task = await asyncio.wait_for(
                    self.task_queue.get(), 
                    timeout=1.0
                )
                
                # 작업 처리
                result = await self._process_ocr_task(task)
                self.results[task.id] = result
                
                # 큐 작업 완료 표시
                self.task_queue.task_done()
                
            except asyncio.TimeoutError:
                # 타임아웃은 정상 (큐가 비어있음)
                continue
            except Exception as e:
                self.logger.error(f"워커 {worker_id} 오류: {e}")
    
    def _on_file_created(self, file_path: Path):
        """파일 생성 이벤트 핸들러"""
        if self.ocr_engine.is_supported_image(file_path):
            # 비동기 작업을 이벤트 루프에 스케줄링
            if self.loop and not self.loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self.add_ocr_task(file_path), 
                    self.loop
                )
    
    def start(self):
        """OCR 관리자 시작"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # 새 이벤트 루프에서 실행
        def run_async_manager():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._async_start())
        
        thread = threading.Thread(target=run_async_manager, daemon=True)
        thread.start()
        
        self.logger.info("AsyncOCRManager 시작됨")
    
    async def _async_start(self):
        """비동기 시작 로직"""
        try:
            # 워커 시작
            self.workers = [
                asyncio.create_task(self._worker(i)) 
                for i in range(self.max_workers)
            ]
            
            # 파일 감시자 시작
            self.file_watcher = FileWatcher(
                self.watch_directory,
                on_created=self._on_file_created
            )
            self.file_watcher.start()
            
            self.logger.info(f"OCR 워커 {self.max_workers}개와 파일 감시자 시작됨")
            
            # 무한 대기
            while self.is_running:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"AsyncOCRManager 실행 오류: {e}")
        finally:
            await self._cleanup()
    
    async def _cleanup(self):
        """리소스 정리"""
        # 파일 감시자 중지
        if self.file_watcher:
            self.file_watcher.stop()
        
        # 워커 취소
        for worker in self.workers:
            worker.cancel()
        
        # 남은 작업 완료 대기
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
    
    def stop(self):
        """OCR 관리자 중지"""
        self.is_running = False
        self.logger.info("AsyncOCRManager 중지됨")
    
    def get_result(self, task_id: int) -> Optional[OCRResult]:
        """작업 결과 조회"""
        return self.results.get(task_id)
    
    def get_queue_size(self) -> int:
        """대기 중인 작업 수"""
        return self.task_queue.qsize() if self.task_queue else 0