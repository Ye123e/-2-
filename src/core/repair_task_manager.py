#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复任务管理系统
提供任务调度、状态跟踪、批量修复和任务队列管理功能
"""

import json
import queue
import threading
import time
from typing import Dict, List, Optional, Callable, Any, Set
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque

from ..models import RepairTask, TaskStatus, DeviceInfo, VulnerabilityReport
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager
from .enhanced_repair_engine import EnhancedRepairEngine, HardeningType


class TaskPriority(Enum):
    """任务优先级"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5


class ScheduleType(Enum):
    """调度类型"""
    IMMEDIATE = "IMMEDIATE"        # 立即执行
    SCHEDULED = "SCHEDULED"        # 定时执行
    RECURRING = "RECURRING"        # 循环执行
    BATCH = "BATCH"               # 批量执行


@dataclass
class TaskSchedule:
    """任务调度配置"""
    schedule_id: str
    schedule_type: ScheduleType
    target_time: Optional[datetime] = None
    interval_minutes: Optional[int] = None  # 循环间隔（分钟）
    max_executions: Optional[int] = None    # 最大执行次数
    devices: List[str] = field(default_factory=list)
    task_config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    
    @property
    def next_execution(self) -> Optional[datetime]:
        """计算下次执行时间"""
        if self.schedule_type == ScheduleType.IMMEDIATE:
            return datetime.now()
        elif self.schedule_type == ScheduleType.SCHEDULED:
            return self.target_time
        elif self.schedule_type == ScheduleType.RECURRING and self.interval_minutes:
            return datetime.now() + timedelta(minutes=self.interval_minutes)
        return None


@dataclass
class BatchRepairJob:
    """批量修复作业"""
    job_id: str
    devices: List[str]
    repair_types: List[str]
    priority: TaskPriority = TaskPriority.MEDIUM
    auto_repair: bool = True
    parallel_execution: bool = True
    max_concurrent: int = 3
    timeout_minutes: int = 30
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "PENDING"
    progress: int = 0
    completed_devices: Set[str] = field(default_factory=set)
    failed_devices: Set[str] = field(default_factory=set)


class RepairTaskQueue:
    """修复任务队列"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.queue = queue.PriorityQueue(maxsize=max_size)
        self.task_registry: Dict[str, RepairTask] = {}
        self._lock = threading.Lock()
    
    def add_task(self, task: RepairTask, priority: TaskPriority = TaskPriority.MEDIUM):
        """添加任务到队列"""
        with self._lock:
            if self.queue.full():
                raise queue.Full("任务队列已满")
            
            # 使用负值使高优先级任务先执行
            priority_value = -priority.value
            queue_item = (priority_value, time.time(), task.task_id, task)
            self.queue.put(queue_item)
            self.task_registry[task.task_id] = task
    
    def get_next_task(self, timeout: Optional[float] = None) -> Optional[RepairTask]:
        """获取下一个任务"""
        try:
            _, _, task_id, task = self.queue.get(timeout=timeout)
            return task
        except queue.Empty:
            return None
    
    def remove_task(self, task_id: str) -> bool:
        """移除任务"""
        with self._lock:
            if task_id in self.task_registry:
                del self.task_registry[task_id]
                return True
            return False
    
    def get_task_count(self) -> int:
        """获取队列中任务数量"""
        return self.queue.qsize()
    
    def is_empty(self) -> bool:
        """检查队列是否为空"""
        return self.queue.empty()


class TaskExecutor(LoggerMixin):
    """任务执行器"""
    
    def __init__(self, repair_engine: EnhancedRepairEngine, worker_count: int = 3):
        self.repair_engine = repair_engine
        self.worker_count = worker_count
        self.task_queue = RepairTaskQueue()
        
        # 工作线程管理
        self.workers: List[threading.Thread] = []
        self.running = False
        self.execution_stats = {
            'tasks_executed': 0,
            'tasks_succeeded': 0,
            'tasks_failed': 0,
            'total_execution_time': 0.0
        }
    
    def start(self):
        """启动任务执行器"""
        if self.running:
            return
        
        self.running = True
        
        # 启动工作线程
        for i in range(self.worker_count):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"RepairWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        self.logger.info(f"任务执行器启动，工作线程数: {self.worker_count}")
    
    def stop(self):
        """停止任务执行器"""
        self.running = False
        
        # 等待所有工作线程结束
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        self.workers.clear()
        self.logger.info("任务执行器已停止")
    
    def submit_task(self, task: RepairTask, priority: TaskPriority = TaskPriority.MEDIUM):
        """提交任务"""
        try:
            self.task_queue.add_task(task, priority)
            self.logger.info(f"任务已提交: {task.task_id} (优先级: {priority.name})")
        except queue.Full:
            self.logger.error(f"任务队列已满，无法提交任务: {task.task_id}")
            raise
    
    def _worker_loop(self):
        """工作线程主循环"""
        worker_name = threading.current_thread().name
        self.logger.info(f"工作线程启动: {worker_name}")
        
        while self.running:
            try:
                # 获取下一个任务
                task = self.task_queue.get_next_task(timeout=1.0)
                if not task:
                    continue
                
                self.logger.info(f"[{worker_name}] 开始执行任务: {task.task_id}")
                start_time = time.time()
                
                # 执行任务
                success = self._execute_task(task)
                
                # 更新统计信息
                execution_time = time.time() - start_time
                self.execution_stats['tasks_executed'] += 1
                self.execution_stats['total_execution_time'] += execution_time
                
                if success:
                    self.execution_stats['tasks_succeeded'] += 1
                    self.logger.info(f"[{worker_name}] 任务执行成功: {task.task_id} "
                                   f"(耗时: {execution_time:.1f}s)")
                else:
                    self.execution_stats['tasks_failed'] += 1
                    self.logger.error(f"[{worker_name}] 任务执行失败: {task.task_id}")
                
            except Exception as e:
                self.logger.error(f"[{worker_name}] 工作线程异常: {e}")
                time.sleep(1.0)  # 避免连续异常导致CPU占用过高
        
        self.logger.info(f"工作线程结束: {worker_name}")
    
    def _execute_task(self, task: RepairTask) -> bool:
        """执行单个任务"""
        try:
            task.start()
            
            if task.task_type == "VULNERABILITY_REPAIR":
                auto_repair = task.details.get('auto_repair', True)
                actual_task_id = self.repair_engine.scan_and_repair_vulnerabilities(
                    task.device_id, auto_repair
                )
                # 等待任务完成
                self._wait_for_task_completion(actual_task_id)
                
            elif task.task_type == "SYSTEM_HARDENING":
                hardening_types = task.details.get('hardening_types', [])
                hardening_enums = [HardeningType(ht) for ht in hardening_types]
                actual_task_id = self.repair_engine.apply_system_hardening(
                    task.device_id, hardening_enums
                )
                self._wait_for_task_completion(actual_task_id)
            
            else:
                self.logger.warning(f"未知任务类型: {task.task_type}")
                task.fail("未知任务类型")
                return False
            
            task.complete()
            return True
            
        except Exception as e:
            self.logger.error(f"任务执行异常: {e}")
            task.fail(str(e))
            return False
    
    def _wait_for_task_completion(self, task_id: str, timeout: int = 1800):  # 30分钟超时
        """等待任务完成"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            repair_task = self.repair_engine.get_repair_status(task_id)
            if repair_task and repair_task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                return
            time.sleep(2.0)
        
        self.logger.warning(f"任务等待超时: {task_id}")


class RepairTaskManager(LoggerMixin):
    """修复任务管理器"""
    
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
        self.repair_engine = EnhancedRepairEngine(device_manager)
        self.task_executor = TaskExecutor(self.repair_engine)
        
        # 任务管理
        self.task_history: List[RepairTask] = []
        self.scheduled_tasks: Dict[str, TaskSchedule] = {}
        self.batch_jobs: Dict[str, BatchRepairJob] = {}
        
        # 调度器
        self.scheduler_thread: Optional[threading.Thread] = None
        self.scheduler_running = False
        
        # 回调函数
        self.task_callbacks: List[Callable[[RepairTask], None]] = []
        self.progress_callbacks: List[Callable[[str, int, str], None]] = []
        
        # 启动任务执行器
        self.task_executor.start()
    
    def __del__(self):
        """析构函数"""
        self.shutdown()
    
    def shutdown(self):
        """关闭管理器"""
        self.stop_scheduler()
        self.task_executor.stop()
    
    def add_task_callback(self, callback: Callable[[RepairTask], None]):
        """添加任务回调"""
        self.task_callbacks.append(callback)
    
    def add_progress_callback(self, callback: Callable[[str, int, str], None]):
        """添加进度回调"""
        self.progress_callbacks.append(callback)
        self.repair_engine.add_progress_callback(callback)
    
    def create_vulnerability_repair_task(self, device_id: str, 
                                       auto_repair: bool = True,
                                       priority: TaskPriority = TaskPriority.MEDIUM) -> str:
        """创建漏洞修复任务"""
        task_id = f"vuln_repair_{device_id}_{int(time.time())}"
        
        task = RepairTask(
            task_id=task_id,
            device_id=device_id,
            task_type="VULNERABILITY_REPAIR",
            status=TaskStatus.PENDING,
            details={'auto_repair': auto_repair}
        )
        
        self.task_executor.submit_task(task, priority)
        self.task_history.append(task)
        
        return task_id
    
    def create_system_hardening_task(self, device_id: str,
                                   hardening_types: List[str] = None,  # pyright: ignore[reportArgumentType]
                                   priority: TaskPriority = TaskPriority.MEDIUM) -> str:
        """创建系统加固任务"""
        if hardening_types is None:
            hardening_types = [ht.value for ht in HardeningType]
        
        task_id = f"hardening_{device_id}_{int(time.time())}"
        
        task = RepairTask(
            task_id=task_id,
            device_id=device_id,
            task_type="SYSTEM_HARDENING",
            status=TaskStatus.PENDING,
            details={'hardening_types': hardening_types}
        )
        
        self.task_executor.submit_task(task, priority)
        self.task_history.append(task)
        
        return task_id
    
    def create_batch_repair_job(self, devices: List[str], 
                              repair_types: List[str],
                              priority: TaskPriority = TaskPriority.MEDIUM,
                              auto_repair: bool = True,
                              parallel_execution: bool = True) -> str:
        """创建批量修复作业"""
        job_id = f"batch_repair_{int(time.time())}"
        
        batch_job = BatchRepairJob(
            job_id=job_id,
            devices=devices,
            repair_types=repair_types,
            priority=priority,
            auto_repair=auto_repair,
            parallel_execution=parallel_execution
        )
        
        self.batch_jobs[job_id] = batch_job
        
        # 在新线程中执行批量任务
        batch_thread = threading.Thread(
            target=self._execute_batch_job,
            args=(batch_job,),
            daemon=True
        )
        batch_thread.start()
        
        return job_id
    
    def _execute_batch_job(self, batch_job: BatchRepairJob):
        """执行批量修复作业"""
        try:
            batch_job.status = "RUNNING"
            self.logger.info(f"开始批量修复作业: {batch_job.job_id}")
            
            total_tasks = len(batch_job.devices) * len(batch_job.repair_types)
            completed_tasks = 0
            
            if batch_job.parallel_execution:
                # 并行执行
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch_job.max_concurrent) as executor:
                    futures = []
                    
                    for device_id in batch_job.devices:
                        for repair_type in batch_job.repair_types:
                            future = executor.submit(
                                self._execute_single_batch_task,
                                batch_job, device_id, repair_type
                            )
                            futures.append((future, device_id))
                    
                    # 等待所有任务完成
                    for future, device_id in futures:
                        try:
                            success = future.result(timeout=batch_job.timeout_minutes * 60)
                            completed_tasks += 1
                            
                            if success:
                                batch_job.completed_devices.add(device_id)
                            else:
                                batch_job.failed_devices.add(device_id)
                            
                            # 更新进度
                            batch_job.progress = int((completed_tasks / total_tasks) * 100)
                            
                        except concurrent.futures.TimeoutError:
                            self.logger.error(f"批量任务超时: {device_id}")
                            batch_job.failed_devices.add(device_id)
                        except Exception as e:
                            self.logger.error(f"批量任务执行异常: {e}")
                            batch_job.failed_devices.add(device_id)
            
            else:
                # 串行执行
                for device_id in batch_job.devices:
                    for repair_type in batch_job.repair_types:
                        success = self._execute_single_batch_task(
                            batch_job, device_id, repair_type
                        )
                        completed_tasks += 1
                        
                        if success:
                            batch_job.completed_devices.add(device_id)
                        else:
                            batch_job.failed_devices.add(device_id)
                        
                        # 更新进度
                        batch_job.progress = int((completed_tasks / total_tasks) * 100)
            
            # 完成批量作业
            batch_job.status = "COMPLETED"
            batch_job.progress = 100
            
            success_count = len(batch_job.completed_devices)
            total_devices = len(batch_job.devices)
            
            self.logger.info(f"批量修复作业完成: {batch_job.job_id} "
                           f"({success_count}/{total_devices} 设备成功)")
            
        except Exception as e:
            self.logger.error(f"批量修复作业异常: {e}")
            batch_job.status = "FAILED"
    
    def _execute_single_batch_task(self, batch_job: BatchRepairJob, 
                                 device_id: str, repair_type: str) -> bool:
        """执行单个批量任务"""
        try:
            if repair_type == "VULNERABILITY_REPAIR":
                task_id = self.create_vulnerability_repair_task(
                    device_id, batch_job.auto_repair, batch_job.priority
                )
            elif repair_type == "SYSTEM_HARDENING":
                task_id = self.create_system_hardening_task(
                    device_id, None, batch_job.priority  # pyright: ignore[reportArgumentType]
                )
            else:
                self.logger.warning(f"未知修复类型: {repair_type}")
                return False
            
            # 等待任务完成（简化版本）
            time.sleep(5)  # 给任务一些执行时间
            return True
            
        except Exception as e:
            self.logger.error(f"单个批量任务执行失败: {e}")
            return False
    
    def schedule_task(self, schedule: TaskSchedule):
        """调度任务"""
        self.scheduled_tasks[schedule.schedule_id] = schedule
        
        if not self.scheduler_running:
            self.start_scheduler()
        
        self.logger.info(f"任务已调度: {schedule.schedule_id}")
    
    def start_scheduler(self):
        """启动调度器"""
        if self.scheduler_running:
            return
        
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()
        self.logger.info("任务调度器已启动")
    
    def stop_scheduler(self):
        """停止调度器"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5.0)
        self.logger.info("任务调度器已停止")
    
    def _scheduler_loop(self):
        """调度器主循环"""
        while self.scheduler_running:
            try:
                current_time = datetime.now()
                
                # 检查所有调度任务
                for schedule_id, schedule in list(self.scheduled_tasks.items()):
                    if not schedule.enabled:
                        continue
                    
                    next_exec = schedule.next_execution
                    if next_exec and next_exec <= current_time:
                        self._execute_scheduled_task(schedule)
                
                time.sleep(10)  # 每10秒检查一次
                
            except Exception as e:
                self.logger.error(f"调度器循环异常: {e}")
                time.sleep(60)  # 异常情况下等待更长时间
    
    def _execute_scheduled_task(self, schedule: TaskSchedule):
        """执行调度任务"""
        try:
            self.logger.info(f"执行调度任务: {schedule.schedule_id}")
            
            for device_id in schedule.devices:
                if 'vulnerability_repair' in schedule.task_config:
                    self.create_vulnerability_repair_task(device_id)
                
                if 'system_hardening' in schedule.task_config:
                    hardening_types = schedule.task_config.get('hardening_types')
                    self.create_system_hardening_task(device_id, hardening_types)  # pyright: ignore[reportArgumentType]
            
            # 更新下次执行时间（对于循环任务）
            if schedule.schedule_type == ScheduleType.RECURRING and schedule.interval_minutes:
                schedule.target_time = datetime.now() + timedelta(minutes=schedule.interval_minutes)
            
        except Exception as e:
            self.logger.error(f"调度任务执行失败: {e}")
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """获取任务统计信息"""
        return {
            'total_tasks': len(self.task_history),
            'pending_tasks': self.task_executor.task_queue.get_task_count(),
            'batch_jobs': len(self.batch_jobs),
            'scheduled_tasks': len(self.scheduled_tasks),
            'executor_stats': self.task_executor.execution_stats,
            'repair_stats': self.repair_engine.get_repair_stats()
        }