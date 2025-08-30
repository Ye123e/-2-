#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复流程异常处理和恢复机制
负责处理修复过程中的各种异常情况并提供恢复策略
"""

import threading
import time
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from enum import Enum
from pathlib import Path

from ..utils.logger import LoggerMixin
from ..models import DeviceInfo, RepairTask, TaskStatus, Issue


class ExceptionType(Enum):
    """异常类型枚举"""
    DEVICE_CONNECTION_LOST = "设备连接丢失"
    PERMISSION_DENIED = "权限被拒绝" 
    STORAGE_FULL = "存储空间不足"
    COMMAND_TIMEOUT = "命令执行超时"
    SYSTEM_ERROR = "系统错误"
    NETWORK_ERROR = "网络错误"
    UNKNOWN_ERROR = "未知错误"


class RecoveryAction(Enum):
    """恢复动作枚举"""
    RETRY = "重试"
    SKIP = "跳过"
    ABORT = "中止"
    ROLLBACK = "回滚"
    WAIT_AND_RETRY = "等待后重试"
    REQUEST_USER_ACTION = "请求用户操作"


class ExceptionPolicy:
    """异常处理策略"""
    
    def __init__(self, exception_type: ExceptionType, max_retries: int = 3,
                 retry_delay: int = 5, recovery_action: RecoveryAction = RecoveryAction.RETRY):
        self.exception_type = exception_type
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.recovery_action = recovery_action
        self.custom_handler: Optional[Callable] = None
    
    def set_custom_handler(self, handler: Callable):
        """设置自定义处理函数"""
        self.custom_handler = handler


class RecoveryContext:
    """恢复上下文信息"""
    
    def __init__(self, task_id: str, device_id: str, operation: str):
        self.task_id = task_id
        self.device_id = device_id
        self.operation = operation
        self.exception_count = 0
        self.last_exception_time = None
        self.recovery_attempts = 0
        self.backup_data: Dict[str, Any] = {}
        self.rollback_commands: List[str] = []
        
    def record_exception(self, exception: Exception):
        """记录异常"""
        self.exception_count += 1
        self.last_exception_time = datetime.now()
    
    def can_retry(self, max_retries: int) -> bool:
        """检查是否可以重试"""
        return self.recovery_attempts < max_retries


class RepairExceptionHandler(LoggerMixin):
    """修复异常处理器"""
    
    def __init__(self, device_manager):
        self.device_manager = device_manager
        self.recovery_contexts: Dict[str, RecoveryContext] = {}
        self.exception_policies: Dict[ExceptionType, ExceptionPolicy] = {}
        
        # 初始化默认策略
        self._init_default_policies()
        
        # 异常回调函数
        self.exception_callbacks: List[Callable] = []
        self.recovery_callbacks: List[Callable] = []
        
        # 备份管理
        self.backup_path = Path("data/backups")
        self.backup_path.mkdir(parents=True, exist_ok=True)
    
    def _init_default_policies(self):
        """初始化默认异常处理策略"""
        # 设备连接丢失 - 重试3次
        self.exception_policies[ExceptionType.DEVICE_CONNECTION_LOST] = ExceptionPolicy(
            ExceptionType.DEVICE_CONNECTION_LOST,
            max_retries=3,
            retry_delay=10,
            recovery_action=RecoveryAction.WAIT_AND_RETRY
        )
        
        # 权限被拒绝 - 跳过或请求用户操作
        self.exception_policies[ExceptionType.PERMISSION_DENIED] = ExceptionPolicy(
            ExceptionType.PERMISSION_DENIED,
            max_retries=1,
            retry_delay=0,
            recovery_action=RecoveryAction.REQUEST_USER_ACTION
        )
        
        # 存储空间不足 - 中止任务
        self.exception_policies[ExceptionType.STORAGE_FULL] = ExceptionPolicy(
            ExceptionType.STORAGE_FULL,
            max_retries=0,
            retry_delay=0,
            recovery_action=RecoveryAction.ABORT
        )
        
        # 命令超时 - 重试2次
        self.exception_policies[ExceptionType.COMMAND_TIMEOUT] = ExceptionPolicy(
            ExceptionType.COMMAND_TIMEOUT,
            max_retries=2,
            retry_delay=5,
            recovery_action=RecoveryAction.RETRY
        )
        
        # 系统错误 - 回滚操作
        self.exception_policies[ExceptionType.SYSTEM_ERROR] = ExceptionPolicy(
            ExceptionType.SYSTEM_ERROR,
            max_retries=1,
            retry_delay=0,
            recovery_action=RecoveryAction.ROLLBACK
        )
    
    def add_exception_callback(self, callback: Callable):
        """添加异常回调"""
        self.exception_callbacks.append(callback)
    
    def add_recovery_callback(self, callback: Callable):
        """添加恢复回调"""
        self.recovery_callbacks.append(callback)
    
    def handle_exception(self, task_id: str, device_id: str, operation: str, 
                        exception: Exception) -> RecoveryAction:
        """
        处理修复过程中的异常
        
        Args:
            task_id: 任务ID
            device_id: 设备ID
            operation: 当前操作
            exception: 异常对象
            
        Returns:
            建议的恢复动作
        """
        try:
            # 获取或创建恢复上下文
            context_key = f"{task_id}_{operation}"
            if context_key not in self.recovery_contexts:
                self.recovery_contexts[context_key] = RecoveryContext(task_id, device_id, operation)
            
            context = self.recovery_contexts[context_key]
            context.record_exception(exception)
            
            # 识别异常类型
            exception_type = self._classify_exception(exception)
            
            self.logger.error(f"修复异常 - 任务: {task_id}, 操作: {operation}, "
                            f"异常类型: {exception_type.value}, 错误: {str(exception)}")
            
            # 通知异常回调
            self._notify_exception_callbacks(task_id, device_id, operation, exception_type, exception)
            
            # 获取处理策略
            policy = self.exception_policies.get(exception_type)
            if not policy:
                policy = self.exception_policies[ExceptionType.UNKNOWN_ERROR]
            
            # 执行恢复策略
            recovery_action = self._execute_recovery_strategy(context, policy, exception)
            
            self.logger.info(f"异常处理完成 - 任务: {task_id}, 恢复动作: {recovery_action.value}")
            
            return recovery_action
            
        except Exception as e:
            self.logger.error(f"异常处理器本身发生异常: {e}")
            return RecoveryAction.ABORT
    
    def _classify_exception(self, exception: Exception) -> ExceptionType:
        """分类异常"""
        error_message = str(exception).lower()
        
        # 设备连接问题
        if any(keyword in error_message for keyword in 
               ['device not found', 'no devices', 'connection refused', 'device offline']):
            return ExceptionType.DEVICE_CONNECTION_LOST
        
        # 权限问题
        elif any(keyword in error_message for keyword in 
                ['permission denied', 'unauthorized', 'access denied']):
            return ExceptionType.PERMISSION_DENIED
        
        # 存储空间问题
        elif any(keyword in error_message for keyword in 
                ['no space left', 'disk full', 'storage full']):
            return ExceptionType.STORAGE_FULL
        
        # 超时问题
        elif any(keyword in error_message for keyword in 
                ['timeout', 'timed out', 'connection timeout']):
            return ExceptionType.COMMAND_TIMEOUT
        
        # 网络问题
        elif any(keyword in error_message for keyword in 
                ['network', 'connection error', 'host unreachable']):
            return ExceptionType.NETWORK_ERROR
        
        # 系统错误
        elif any(keyword in error_message for keyword in 
                ['system error', 'kernel panic', 'segmentation fault']):
            return ExceptionType.SYSTEM_ERROR
        
        else:
            return ExceptionType.UNKNOWN_ERROR
    
    def _execute_recovery_strategy(self, context: RecoveryContext, 
                                 policy: ExceptionPolicy, exception: Exception) -> RecoveryAction:
        """执行恢复策略"""
        
        # 检查是否有自定义处理函数
        if policy.custom_handler:
            try:
                return policy.custom_handler(context, exception)
            except Exception as e:
                self.logger.error(f"自定义异常处理函数执行失败: {e}")
        
        # 执行默认策略
        if policy.recovery_action == RecoveryAction.RETRY:
            return self._handle_retry(context, policy)
        
        elif policy.recovery_action == RecoveryAction.WAIT_AND_RETRY:
            return self._handle_wait_and_retry(context, policy)
        
        elif policy.recovery_action == RecoveryAction.SKIP:
            return self._handle_skip(context)
        
        elif policy.recovery_action == RecoveryAction.ROLLBACK:
            return self._handle_rollback(context)
        
        elif policy.recovery_action == RecoveryAction.REQUEST_USER_ACTION:
            return self._handle_request_user_action(context, exception)
        
        elif policy.recovery_action == RecoveryAction.ABORT:
            return self._handle_abort(context)
        
        else:
            return RecoveryAction.ABORT
    
    def _handle_retry(self, context: RecoveryContext, policy: ExceptionPolicy) -> RecoveryAction:
        """处理重试"""
        if context.can_retry(policy.max_retries):
            context.recovery_attempts += 1
            
            if policy.retry_delay > 0:
                self.logger.info(f"等待 {policy.retry_delay} 秒后重试...")
                time.sleep(policy.retry_delay)
            
            self.logger.info(f"重试操作 - 第 {context.recovery_attempts} 次")
            return RecoveryAction.RETRY
        else:
            self.logger.warning(f"已达到最大重试次数 {policy.max_retries}，中止操作")
            return RecoveryAction.ABORT
    
    def _handle_wait_and_retry(self, context: RecoveryContext, policy: ExceptionPolicy) -> RecoveryAction:
        """处理等待后重试"""
        if context.can_retry(policy.max_retries):
            context.recovery_attempts += 1
            
            # 特殊处理设备连接丢失
            if policy.exception_type == ExceptionType.DEVICE_CONNECTION_LOST:
                success = self._attempt_device_reconnection(context.device_id, policy.retry_delay)
                if success:
                    self.logger.info("设备重连成功，继续执行操作")
                    return RecoveryAction.RETRY
                else:
                    return self._handle_retry(context, policy)
            else:
                return self._handle_retry(context, policy)
        else:
            return RecoveryAction.ABORT
    
    def _handle_skip(self, context: RecoveryContext) -> RecoveryAction:
        """处理跳过操作"""
        self.logger.info(f"跳过当前操作: {context.operation}")
        return RecoveryAction.SKIP
    
    def _handle_rollback(self, context: RecoveryContext) -> RecoveryAction:
        """处理回滚操作"""
        self.logger.info(f"开始回滚操作: {context.operation}")
        
        try:
            # 执行回滚命令
            for command in reversed(context.rollback_commands):
                self.device_manager.adb_manager.execute_command(context.device_id, command)
            
            # 恢复备份数据
            if context.backup_data:
                self._restore_backup_data(context)
            
            self.logger.info("回滚操作完成")
            return RecoveryAction.ROLLBACK
            
        except Exception as e:
            self.logger.error(f"回滚操作失败: {e}")
            return RecoveryAction.ABORT
    
    def _handle_request_user_action(self, context: RecoveryContext, exception: Exception) -> RecoveryAction:
        """处理请求用户操作"""
        self.logger.warning(f"需要用户干预 - 任务: {context.task_id}, 错误: {str(exception)}")
        
        # 通知用户需要手动处理
        self._notify_recovery_callbacks(context.task_id, context.device_id, 
                                      RecoveryAction.REQUEST_USER_ACTION, str(exception))
        
        return RecoveryAction.REQUEST_USER_ACTION
    
    def _handle_abort(self, context: RecoveryContext) -> RecoveryAction:
        """处理中止操作"""
        self.logger.error(f"中止修复操作 - 任务: {context.task_id}")
        
        # 清理恢复上下文
        context_key = f"{context.task_id}_{context.operation}"
        if context_key in self.recovery_contexts:
            del self.recovery_contexts[context_key]
        
        return RecoveryAction.ABORT
    
    def _attempt_device_reconnection(self, device_id: str, timeout: int = 30) -> bool:
        """尝试重新连接设备"""
        self.logger.info(f"尝试重新连接设备: {device_id}")
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # 刷新设备列表
                devices = self.device_manager.scan_devices()
                
                # 检查设备是否已重新连接
                for device in devices:
                    if device.device_id == device_id:
                        # 测试连接
                        if self.device_manager.test_device_connectivity(device_id):
                            self.logger.info(f"设备重连成功: {device_id}")
                            return True
                
                time.sleep(2)  # 等待2秒后再次尝试
                
            except Exception as e:
                self.logger.error(f"重连尝试失败: {e}")
                time.sleep(2)
        
        self.logger.warning(f"设备重连超时: {device_id}")
        return False
    
    def create_backup(self, task_id: str, device_id: str, operation: str, data: Dict[str, Any]):
        """创建操作备份"""
        try:
            context_key = f"{task_id}_{operation}"
            if context_key not in self.recovery_contexts:
                self.recovery_contexts[context_key] = RecoveryContext(task_id, device_id, operation)
            
            context = self.recovery_contexts[context_key]
            context.backup_data.update(data)
            
            # 保存备份到文件
            backup_file = self.backup_path / f"{task_id}_{operation}_{int(time.time())}.json"
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'task_id': task_id,
                    'device_id': device_id,
                    'operation': operation,
                    'timestamp': datetime.now().isoformat(),
                    'backup_data': data
                }, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"备份已创建: {backup_file}")
            
        except Exception as e:
            self.logger.error(f"创建备份失败: {e}")
    
    def add_rollback_command(self, task_id: str, operation: str, command: str):
        """添加回滚命令"""
        context_key = f"{task_id}_{operation}"
        if context_key not in self.recovery_contexts:
            return
        
        context = self.recovery_contexts[context_key]
        context.rollback_commands.append(command)
    
    def _restore_backup_data(self, context: RecoveryContext):
        """恢复备份数据"""
        # 这里可以实现具体的数据恢复逻辑
        # 根据备份数据的类型执行相应的恢复操作
        pass
    
    def _notify_exception_callbacks(self, task_id: str, device_id: str, operation: str, 
                                  exception_type: ExceptionType, exception: Exception):
        """通知异常回调"""
        for callback in self.exception_callbacks:
            try:
                callback(task_id, device_id, operation, exception_type, exception)
            except Exception as e:
                self.logger.error(f"异常回调执行失败: {e}")
    
    def _notify_recovery_callbacks(self, task_id: str, device_id: str, 
                                 recovery_action: RecoveryAction, message: str):
        """通知恢复回调"""
        for callback in self.recovery_callbacks:
            try:
                callback(task_id, device_id, recovery_action, message)
            except Exception as e:
                self.logger.error(f"恢复回调执行失败: {e}")
    
    def get_recovery_statistics(self) -> Dict[str, Any]:
        """获取恢复统计信息"""
        total_exceptions = len(self.recovery_contexts)
        exception_types = {}
        
        for context in self.recovery_contexts.values():
            # 这里可以统计异常类型分布
            pass
        
        return {
            'total_exceptions': total_exceptions,
            'exception_types': exception_types,
            'active_contexts': len(self.recovery_contexts)
        }
    
    def cleanup_old_contexts(self, max_age_hours: int = 24):
        """清理过期的恢复上下文"""
        current_time = datetime.now()
        expired_contexts = []
        
        for key, context in self.recovery_contexts.items():
            if context.last_exception_time:
                age_hours = (current_time - context.last_exception_time).total_seconds() / 3600
                if age_hours > max_age_hours:
                    expired_contexts.append(key)
        
        for key in expired_contexts:
            del self.recovery_contexts[key]
        
        if expired_contexts:
            self.logger.info(f"清理了 {len(expired_contexts)} 个过期的恢复上下文")


class RepairTaskMonitor(LoggerMixin):
    """修复任务监控器"""
    
    def __init__(self, exception_handler: RepairExceptionHandler):
        self.exception_handler = exception_handler
        self.monitored_tasks: Dict[str, Dict] = {}
        self.monitoring_thread = None
        self.monitoring = False
    
    def start_monitoring(self):
        """开始监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitor_tasks, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("修复任务监控器已启动")
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
        self.logger.info("修复任务监控器已停止")
    
    def add_task(self, task_id: str, device_id: str, timeout: int = 300):
        """添加监控任务"""
        self.monitored_tasks[task_id] = {
            'device_id': device_id,
            'start_time': datetime.now(),
            'timeout': timeout,
            'last_heartbeat': datetime.now()
        }
    
    def update_heartbeat(self, task_id: str):
        """更新任务心跳"""
        if task_id in self.monitored_tasks:
            self.monitored_tasks[task_id]['last_heartbeat'] = datetime.now()
    
    def remove_task(self, task_id: str):
        """移除监控任务"""
        if task_id in self.monitored_tasks:
            del self.monitored_tasks[task_id]
    
    def _monitor_tasks(self):
        """监控任务线程"""
        while self.monitoring:
            try:
                current_time = datetime.now()
                timeout_tasks = []
                
                for task_id, task_info in self.monitored_tasks.items():
                    # 检查任务是否超时
                    elapsed = (current_time - task_info['last_heartbeat']).total_seconds()
                    if elapsed > task_info['timeout']:
                        timeout_tasks.append(task_id)
                
                # 处理超时任务
                for task_id in timeout_tasks:
                    self._handle_task_timeout(task_id)
                
                time.sleep(10)  # 每10秒检查一次
                
            except Exception as e:
                self.logger.error(f"任务监控异常: {e}")
                time.sleep(10)
    
    def _handle_task_timeout(self, task_id: str):
        """处理任务超时"""
        if task_id not in self.monitored_tasks:
            return
        
        task_info = self.monitored_tasks[task_id]
        device_id = task_info['device_id']
        
        self.logger.warning(f"检测到任务超时: {task_id}")
        
        # 通过异常处理器处理超时
        timeout_exception = TimeoutError(f"修复任务超时: {task_id}")
        self.exception_handler.handle_exception(task_id, device_id, "task_execution", timeout_exception)
        
        # 移除超时任务
        self.remove_task(task_id)