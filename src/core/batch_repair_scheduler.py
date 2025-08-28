#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量修复和修复计划调度器
提供批量修复执行、智能调度和任务管理功能
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor, Future

from ..models import RepairResult, RepairStatus, Priority
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager
from .repair_verification_engine import RepairRecoveryManager


class ScheduleType(Enum):
    """调度类型"""
    IMMEDIATE = "IMMEDIATE"
    SCHEDULED = "SCHEDULED"  
    BATCH = "BATCH"
    DEPENDENCY = "DEPENDENCY"


@dataclass
class BatchRepairTask:
    """批量修复任务"""
    task_id: str
    device_id: str
    repair_operations: List[Dict[str, Any]]
    schedule_type: ScheduleType
    scheduled_time: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)
    priority: Priority = Priority.MEDIUM
    max_retries: int = 3
    retry_delay: int = 60
    status: str = "PENDING"
    created_time: datetime = field(default_factory=datetime.now)
    started_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None
    results: List[RepairResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class RepairPlan:
    """修复计划"""
    plan_id: str
    name: str
    description: str
    batch_tasks: List[BatchRepairTask]
    execution_strategy: str = "SEQUENTIAL"
    created_time: datetime = field(default_factory=datetime.now)
    estimated_duration: int = 0
    status: str = "CREATED"


class BatchRepairExecutor(LoggerMixin):
    """批量修复执行器"""
    
    def __init__(self, device_manager: DeviceManager, recovery_manager: RepairRecoveryManager):
        self.device_manager = device_manager
        self.recovery_manager = recovery_manager
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.running_tasks: Dict[str, Future] = {}
        
    def execute_batch_task(self, batch_task: BatchRepairTask) -> Dict[str, Any]:
        """执行批量修复任务"""
        try:
            batch_task.status = "RUNNING"
            batch_task.started_time = datetime.now()
            
            results = []
            errors = []
            
            for operation in batch_task.repair_operations:
                try:
                    # 执行单个修复操作
                    result = self._execute_single_repair(batch_task.device_id, operation)
                    results.append(result)
                    
                    if not result.get('success', False):
                        errors.append(f"修复失败: {operation.get('type', 'unknown')}")
                        
                except Exception as e:
                    error_msg = f"操作执行失败: {str(e)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)
            
            batch_task.results = results
            batch_task.errors = errors
            batch_task.status = "COMPLETED" if not errors else "FAILED"
            batch_task.completed_time = datetime.now()
            
            return {
                'task_id': batch_task.task_id,
                'status': batch_task.status,
                'results': results,
                'errors': errors,
                'execution_time': (batch_task.completed_time - batch_task.started_time).total_seconds()
            }
            
        except Exception as e:
            batch_task.status = "ERROR"
            batch_task.errors.append(str(e))
            batch_task.completed_time = datetime.now()
            self.logger.error(f"批量任务执行失败: {e}")
            return {'task_id': batch_task.task_id, 'status': 'ERROR', 'error': str(e)}
    
    def _execute_single_repair(self, device_id: str, operation: Dict[str, Any]) -> Dict[str, Any]:
        """执行单个修复操作"""
        repair_type = operation.get('type', 'unknown')
        target_path = operation.get('target_path', '')
        
        # 根据修复类型选择修复方法
        repair_method = self._get_repair_method(repair_type)
        
        if repair_method:
            return self.recovery_manager.safe_repair_with_verification(
                device_id=device_id,
                repair_operation=repair_method,
                operation_type=repair_type,
                target_path=target_path,
                **operation.get('parameters', {})
            )
        else:
            return {'success': False, 'error': f'未知的修复类型: {repair_type}'}
    
    def _get_repair_method(self, repair_type: str) -> Optional[Callable]:
        """获取修复方法"""
        repair_methods = {
            'permission_fix': self._fix_permission,
            'config_fix': self._fix_configuration,
            'service_fix': self._fix_service,
            'app_removal': self._remove_app
        }
        return repair_methods.get(repair_type)
    
    def _fix_permission(self, device_id: str, **kwargs) -> RepairResult:
        """修复权限问题"""
        target_path = kwargs.get('target_path', '')
        permissions = kwargs.get('permissions', '644')
        
        result = self.device_manager.execute_command(device_id, f"chmod {permissions} {target_path}")
        
        return RepairResult(
            repair_id=f"perm_{int(time.time())}",
            repair_type="permission_fix",
            target_path=target_path,
            target_value=permissions,
            status=RepairStatus.SUCCESS if result else RepairStatus.FAILED,
            details={'command_result': result}
        )
    
    def _fix_configuration(self, device_id: str, **kwargs) -> RepairResult:
        """修复配置问题"""
        config_file = kwargs.get('target_path', '')
        new_value = kwargs.get('new_value', '')
        
        result = self.device_manager.execute_command(device_id, f"echo '{new_value}' > {config_file}")
        
        return RepairResult(
            repair_id=f"config_{int(time.time())}",
            repair_type="config_fix",
            target_path=config_file,
            target_value=new_value,
            status=RepairStatus.SUCCESS if result else RepairStatus.FAILED,
            details={'new_value': new_value}
        )
    
    def _fix_service(self, device_id: str, **kwargs) -> RepairResult:
        """修复服务问题"""
        service_name = kwargs.get('service_name', '')
        action = kwargs.get('action', 'restart')
        
        result = self.device_manager.execute_command(device_id, f"setprop ctl.{action} {service_name}")
        
        return RepairResult(
            repair_id=f"service_{int(time.time())}",
            repair_type="service_fix",
            target_path=service_name,
            target_value=action,
            status=RepairStatus.SUCCESS if result else RepairStatus.FAILED,
            details={'service_name': service_name, 'action': action}
        )
    
    def _remove_app(self, device_id: str, **kwargs) -> RepairResult:
        """移除应用"""
        package_name = kwargs.get('package_name', '')
        
        result = self.device_manager.execute_command(device_id, f"pm uninstall {package_name}")
        
        return RepairResult(
            repair_id=f"removal_{int(time.time())}",
            repair_type="app_removal", 
            target_path=package_name,
            target_value="uninstalled",
            status=RepairStatus.SUCCESS if result and 'Success' in result else RepairStatus.FAILED,
            details={'package_name': package_name, 'result': result}
        )


class RepairScheduler(LoggerMixin):
    """修复计划调度器"""
    
    def __init__(self, batch_executor: BatchRepairExecutor):
        self.batch_executor = batch_executor
        self.scheduled_tasks: Dict[str, BatchRepairTask] = {}
        self.repair_plans: Dict[str, RepairPlan] = {}
        self.scheduler_running = False
        self.scheduler_thread = None
        
    def add_batch_task(self, batch_task: BatchRepairTask):
        """添加批量任务"""
        self.scheduled_tasks[batch_task.task_id] = batch_task
        self.logger.info(f"批量任务已添加: {batch_task.task_id}")
    
    def create_repair_plan(self, plan_name: str, description: str, tasks: List[BatchRepairTask]) -> str:
        """创建修复计划"""
        plan_id = f"plan_{int(time.time())}_{hash(plan_name) % 1000}"
        
        # 估算执行时间
        estimated_duration = sum(len(task.repair_operations) * 30 for task in tasks)  # 假设每个操作30秒
        
        repair_plan = RepairPlan(
            plan_id=plan_id,
            name=plan_name,
            description=description,
            batch_tasks=tasks,
            estimated_duration=estimated_duration
        )
        
        self.repair_plans[plan_id] = repair_plan
        
        # 将计划中的任务添加到调度器
        for task in tasks:
            self.add_batch_task(task)
        
        self.logger.info(f"修复计划已创建: {plan_id}")
        return plan_id
    
    def start_scheduler(self):
        """启动调度器"""
        if not self.scheduler_running:
            self.scheduler_running = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
            self.scheduler_thread.daemon = True
            self.scheduler_thread.start()
            self.logger.info("修复调度器已启动")
    
    def stop_scheduler(self):
        """停止调度器"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        self.logger.info("修复调度器已停止")
    
    def _scheduler_loop(self):
        """调度器主循环"""
        while self.scheduler_running:
            try:
                self._process_scheduled_tasks()
                time.sleep(30)  # 每30秒检查一次
            except Exception as e:
                self.logger.error(f"调度器循环错误: {e}")
                time.sleep(60)
    
    def _process_scheduled_tasks(self):
        """处理计划任务"""
        current_time = datetime.now()
        
        ready_tasks = []
        for task_id, task in self.scheduled_tasks.items():
            if task.status == "PENDING" and self._is_task_ready(task, current_time):
                ready_tasks.append(task)
        
        # 按优先级排序
        ready_tasks.sort(key=lambda t: self._get_priority_value(t.priority), reverse=True)
        
        # 执行就绪的任务
        for task in ready_tasks[:2]:  # 限制并发执行数量
            future = self.batch_executor.executor.submit(self.batch_executor.execute_batch_task, task)
            self.batch_executor.running_tasks[task.task_id] = future
            task.status = "SCHEDULED"
    
    def _is_task_ready(self, task: BatchRepairTask, current_time: datetime) -> bool:
        """检查任务是否就绪"""
        # 检查时间条件
        if task.scheduled_time and current_time < task.scheduled_time:
            return False
        
        # 检查依赖条件
        for dep_id in task.dependencies:
            dep_task = self.scheduled_tasks.get(dep_id)
            if not dep_task or dep_task.status != "COMPLETED":
                return False
        
        return True
    
    def _get_priority_value(self, priority: Priority) -> int:
        """获取优先级数值"""
        priority_values = {
            Priority.URGENT: 4,
            Priority.HIGH: 3,
            Priority.MEDIUM: 2,
            Priority.LOW: 1
        }
        return priority_values.get(priority, 1)


class RepairPlanManager(LoggerMixin):
    """修复计划管理器"""
    
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
        self.recovery_manager = RepairRecoveryManager(device_manager)
        self.batch_executor = BatchRepairExecutor(device_manager, self.recovery_manager)
        self.scheduler = RepairScheduler(self.batch_executor)
        
    def create_batch_repair_plan(self, device_id: str, vulnerabilities: List[Dict[str, Any]], 
                                strategy: str = "PRIORITY_BASED") -> str:
        """创建批量修复计划"""
        try:
            # 根据策略生成修复任务
            if strategy == "PRIORITY_BASED":
                tasks = self._create_priority_based_tasks(device_id, vulnerabilities)
            elif strategy == "CATEGORY_BASED":
                tasks = self._create_category_based_tasks(device_id, vulnerabilities)
            else:
                tasks = self._create_sequential_tasks(device_id, vulnerabilities)
            
            # 创建修复计划
            plan_id = self.scheduler.create_repair_plan(
                plan_name=f"修复计划_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                description=f"设备{device_id}的{len(vulnerabilities)}个漏洞修复计划",
                tasks=tasks
            )
            
            return plan_id
            
        except Exception as e:
            self.logger.error(f"创建批量修复计划失败: {e}")
            return ""
    
    def _create_priority_based_tasks(self, device_id: str, vulnerabilities: List[Dict[str, Any]]) -> List[BatchRepairTask]:
        """基于优先级创建任务"""
        tasks = []
        
        # 按优先级分组
        priority_groups = {'URGENT': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        
        for vuln in vulnerabilities:
            priority = vuln.get('repair_recommendation', {}).get('priority', 'LOW')
            if priority in priority_groups:
                priority_groups[priority].append(vuln)
        
        # 为每个优先级创建批量任务
        for priority, vulns in priority_groups.items():
            if vulns:
                operations = [self._vuln_to_operation(vuln) for vuln in vulns]
                
                task = BatchRepairTask(
                    task_id=f"batch_{priority.lower()}_{int(time.time())}",
                    device_id=device_id,
                    repair_operations=operations,
                    schedule_type=ScheduleType.BATCH,
                    priority=Priority[priority] if priority in ['URGENT', 'HIGH', 'MEDIUM', 'LOW'] else Priority.MEDIUM
                )
                tasks.append(task)
        
        return tasks
    
    def _create_category_based_tasks(self, device_id: str, vulnerabilities: List[Dict[str, Any]]) -> List[BatchRepairTask]:
        """基于类别创建任务"""
        tasks = []
        
        # 按类别分组
        category_groups = {}
        for vuln in vulnerabilities:
            category = vuln.get('category', 'other')
            if category not in category_groups:
                category_groups[category] = []
            category_groups[category].append(vuln)
        
        # 为每个类别创建任务
        for category, vulns in category_groups.items():
            operations = [self._vuln_to_operation(vuln) for vuln in vulns]
            
            task = BatchRepairTask(
                task_id=f"batch_{category}_{int(time.time())}",
                device_id=device_id,
                repair_operations=operations,
                schedule_type=ScheduleType.BATCH
            )
            tasks.append(task)
        
        return tasks
    
    def _create_sequential_tasks(self, device_id: str, vulnerabilities: List[Dict[str, Any]]) -> List[BatchRepairTask]:
        """创建顺序任务"""
        operations = [self._vuln_to_operation(vuln) for vuln in vulnerabilities]
        
        task = BatchRepairTask(
            task_id=f"batch_sequential_{int(time.time())}",
            device_id=device_id,
            repair_operations=operations,
            schedule_type=ScheduleType.BATCH
        )
        
        return [task]
    
    def _vuln_to_operation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """将漏洞转换为修复操作"""
        repair_type = vuln.get('type', 'config_fix')
        
        operation = {
            'type': repair_type,
            'target_path': vuln.get('target_path', '/system/etc/security'),
            'vulnerability_id': vuln.get('id', 'unknown'),
            'parameters': {}
        }
        
        # 根据漏洞类型添加特定参数
        if repair_type == 'permission_fix':
            operation['parameters']['permissions'] = vuln.get('recommended_permissions', '644')
        elif repair_type == 'config_fix':
            operation['parameters']['new_value'] = vuln.get('recommended_value', '')
        elif repair_type == 'app_removal':
            operation['parameters']['package_name'] = vuln.get('package_name', '')
        
        return operation
    
    def execute_repair_plan(self, plan_id: str) -> Dict[str, Any]:
        """执行修复计划"""
        try:
            plan = self.scheduler.repair_plans.get(plan_id)
            if not plan:
                return {'success': False, 'error': '修复计划不存在'}
            
            plan.status = "EXECUTING"
            
            # 启动调度器
            if not self.scheduler.scheduler_running:
                self.scheduler.start_scheduler()
            
            return {
                'success': True,
                'plan_id': plan_id,
                'task_count': len(plan.batch_tasks),
                'estimated_duration': plan.estimated_duration,
                'status': 'EXECUTING'
            }
            
        except Exception as e:
            self.logger.error(f"执行修复计划失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_plan_status(self, plan_id: str) -> Dict[str, Any]:
        """获取计划状态"""
        try:
            plan = self.scheduler.repair_plans.get(plan_id)
            if not plan:
                return {'error': '计划不存在'}
            
            task_statuses = [task.status for task in plan.batch_tasks]
            completed_tasks = sum(1 for status in task_statuses if status == "COMPLETED")
            failed_tasks = sum(1 for status in task_statuses if status == "FAILED")
            
            return {
                'plan_id': plan_id,
                'status': plan.status,
                'total_tasks': len(plan.batch_tasks),
                'completed_tasks': completed_tasks,
                'failed_tasks': failed_tasks,
                'progress_percentage': (completed_tasks / len(plan.batch_tasks)) * 100 if plan.batch_tasks else 0
            }
            
        except Exception as e:
            self.logger.error(f"获取计划状态失败: {e}")
            return {'error': str(e)}
    
    def cancel_repair_plan(self, plan_id: str) -> bool:
        """取消修复计划"""
        try:
            plan = self.scheduler.repair_plans.get(plan_id)
            if plan:
                plan.status = "CANCELLED"
                
                # 取消相关的未执行任务
                for task in plan.batch_tasks:
                    if task.status in ["PENDING", "SCHEDULED"]:
                        task.status = "CANCELLED"
                
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"取消修复计划失败: {e}")
            return False