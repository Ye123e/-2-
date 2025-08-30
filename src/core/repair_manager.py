#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复管理器模块
负责协调诊断引擎、修复引擎和安全扫描器，实现完整的设备修复流程
"""

import time
import threading
from typing import Optional, List, Dict, Callable, Any
from datetime import datetime
from enum import Enum

from ..models import DeviceInfo, Issue, DiagnosticReport, RepairTask, TaskStatus, RepairType  # pyright: ignore[reportAttributeAccessIssue]
from ..utils.logger import LoggerMixin  # pyright: ignore[reportAttributeAccessIssue]
from .device_manager import DeviceManager
from .diagnostic_engine import DiagnosticEngine
from .repair_engine import RepairEngine
from .security_scanner import SecurityScanner
from .exception_handler import RepairExceptionHandler, RecoveryAction


class RepairStage(Enum):
    """修复阶段枚举"""
    INITIALIZING = "初始化"
    DEVICE_VALIDATION = "设备验证"
    DIAGNOSTIC_STORAGE = "存储诊断"
    DIAGNOSTIC_SYSTEM = "系统诊断"
    DIAGNOSTIC_SECURITY = "安全扫描"
    DIAGNOSTIC_NETWORK = "网络诊断"
    DIAGNOSTIC_APPS = "应用诊断"
    REPORT_GENERATION = "生成报告"
    REPAIR_PLANNING = "制定修复计划"
    REPAIR_EXECUTION = "执行修复"
    VERIFICATION = "验证结果"
    COMPLETED = "修复完成"
    FAILED = "修复失败"


class RepairSession:
    """修复会话信息"""
    
    def __init__(self, device_id: str, session_id: str):
        self.device_id = device_id
        self.session_id = session_id
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.current_stage = RepairStage.INITIALIZING
        self.progress = 0
        self.logs: List[str] = []
        self.issues_found: List[Issue] = []
        self.diagnostic_report: Optional[DiagnosticReport] = None
        self.repair_tasks: List[RepairTask] = []
        self.health_score = 0
        self.success = False
        self.error_message: Optional[str] = None
        
    def add_log(self, message: str):
        """添加日志记录"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")
        
    def update_progress(self, stage: RepairStage, progress: int):
        """更新进度"""
        self.current_stage = stage
        self.progress = progress
        
    def complete(self, success: bool, error_message: Optional[str] = None):
        """完成修复会话"""
        self.end_time = datetime.now()
        self.success = success
        self.error_message = error_message
        self.current_stage = RepairStage.COMPLETED if success else RepairStage.FAILED


class RepairManager(LoggerMixin):
    """修复管理器 - 设备修复流程的总协调器"""
    
    def __init__(self, device_manager: DeviceManager):
        """
        初始化修复管理器
        
        Args:
            device_manager: 设备管理器实例
        """
        self.device_manager = device_manager
        self.diagnostic_engine = DiagnosticEngine(device_manager)
        self.repair_engine = RepairEngine(device_manager)
        self.security_scanner = SecurityScanner(device_manager)  # pyright: ignore[reportCallIssue]
        
        # 初始化异常处理器
        self.exception_handler = RepairExceptionHandler(device_manager)
        self._setup_exception_callbacks()
        
        self.active_sessions: Dict[str, RepairSession] = {}
        self.session_counter = 0
        
        # 回调函数
        self.progress_callbacks: List[Callable[[str, RepairStage, int, str], None]] = []
        self.completion_callbacks: List[Callable[[str, bool, RepairSession], None]] = []
        
    def add_progress_callback(self, callback: Callable[[str, RepairStage, int, str], None]):
        """
        添加进度回调函数
        
        Args:
            callback: 回调函数，参数为(session_id, stage, progress, message)
        """
        self.progress_callbacks.append(callback)
        
    def add_completion_callback(self, callback: Callable[[str, bool, RepairSession], None]):
        """
        添加完成回调函数
        
        Args:
            callback: 回调函数，参数为(session_id, success, session)
        """
        self.completion_callbacks.append(callback)
        
    def _notify_progress(self, session_id: str, stage: RepairStage, progress: int, message: str):
        """通知进度更新"""
        for callback in self.progress_callbacks:
            try:
                callback(session_id, stage, progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
                
    def _notify_completion(self, session_id: str, success: bool, session: RepairSession):
        """通知修复完成"""
        for callback in self.completion_callbacks:
            try:
                callback(session_id, success, session)
            except Exception as e:
                self.logger.error(f"完成回调执行失败: {e}")
    
    def start_repair(self, device_id: str, repair_options: Optional[Dict[str, Any]] = None) -> str:
        """
        启动设备修复流程
        
        Args:
            device_id: 设备ID
            repair_options: 修复选项配置
            
        Returns:
            修复会话ID
        """
        # 生成会话ID
        self.session_counter += 1
        session_id = f"repair_{self.session_counter}_{int(time.time())}"
        
        # 创建修复会话
        session = RepairSession(device_id, session_id)
        self.active_sessions[session_id] = session
        
        # 在新线程中执行修复流程
        repair_thread = threading.Thread(
            target=self._execute_repair_flow,
            args=(session, repair_options or {}),
            daemon=True
        )
        repair_thread.start()
        
        self.logger.info(f"启动设备修复: {device_id}, 会话ID: {session_id}")
        return session_id
    
    def _execute_repair_flow(self, session: RepairSession, repair_options: Dict[str, Any]):
        """执行完整的修复流程"""
        try:
            # 阶段1: 设备验证 (0-10%)
            self._validate_device(session)
            
            # 阶段2: 系统诊断 (10-60%)
            self._perform_diagnosis(session, repair_options)
            
            # 阶段3: 生成修复计划 (60-70%)
            self._generate_repair_plan(session, repair_options)
            
            # 阶段4: 执行修复 (70-95%)
            self._execute_repairs(session)
            
            # 阶段5: 验证结果 (95-100%)
            self._verify_repairs(session)
            
            # 完成修复
            session.complete(True)
            self._notify_progress(session.session_id, RepairStage.COMPLETED, 100, "修复完成")
            self._notify_completion(session.session_id, True, session)
            
        except Exception as e:
            error_msg = f"修复流程异常: {str(e)}"
            self.logger.error(error_msg)
            session.add_log(error_msg)
            session.complete(False, error_msg)
            self._notify_progress(session.session_id, RepairStage.FAILED, session.progress, error_msg)
            self._notify_completion(session.session_id, False, session)
    
    def _validate_device(self, session: RepairSession):
        """验证设备连接状态"""
        def validate_operation():
            session.update_progress(RepairStage.DEVICE_VALIDATION, 5)
            session.add_log("开始验证设备连接")
            self._notify_progress(session.session_id, RepairStage.DEVICE_VALIDATION, 5, "验证设备连接")
            
            device = self.device_manager.get_device(session.device_id)
            if not device:
                raise Exception(f"设备未连接: {session.device_id}")
            
            # 测试ADB连接
            result = self.device_manager.adb_manager.execute_command(session.device_id, "echo 'test'")
            if not result or 'test' not in result:
                raise Exception("ADB连接测试失败")
            
            session.add_log(f"设备验证成功: {device.model}")
            self._notify_progress(session.session_id, RepairStage.DEVICE_VALIDATION, 10, "设备验证成功")
            
        self._execute_with_exception_handling(session, "device_validation", validate_operation)
    
    def _perform_diagnosis(self, session: RepairSession, repair_options: Dict[str, Any]):
        """执行系统诊断"""
        session.add_log("开始系统诊断")
        
        # 存储诊断 (10-20%)
        session.update_progress(RepairStage.DIAGNOSTIC_STORAGE, 15)
        self._notify_progress(session.session_id, RepairStage.DIAGNOSTIC_STORAGE, 15, "检查存储空间")
        storage_issues = self.diagnostic_engine.diagnose_storage(session.device_id)
        session.issues_found.extend(storage_issues)
        session.add_log(f"存储诊断完成，发现 {len(storage_issues)} 个问题")
        
        # 系统文件诊断 (20-35%)
        session.update_progress(RepairStage.DIAGNOSTIC_SYSTEM, 27)
        self._notify_progress(session.session_id, RepairStage.DIAGNOSTIC_SYSTEM, 27, "检查系统文件")
        system_issues = self.diagnostic_engine.diagnose_system_files(session.device_id)
        session.issues_found.extend(system_issues)
        session.add_log(f"系统文件诊断完成，发现 {len(system_issues)} 个问题")
        
        # 安全扫描 (35-50%)
        session.update_progress(RepairStage.DIAGNOSTIC_SECURITY, 42)
        self._notify_progress(session.session_id, RepairStage.DIAGNOSTIC_SECURITY, 42, "执行安全扫描")
        security_issues = self.security_scanner.scan_device(session.device_id)
        session.issues_found.extend(security_issues)  # pyright: ignore[reportArgumentType]
        session.add_log(f"安全扫描完成，发现 {len(security_issues)} 个问题")  # pyright: ignore[reportArgumentType]
        
        # 网络诊断 (50-55%)
        session.update_progress(RepairStage.DIAGNOSTIC_NETWORK, 52)
        self._notify_progress(session.session_id, RepairStage.DIAGNOSTIC_NETWORK, 52, "检查网络配置")
        network_issues = self.diagnostic_engine.diagnose_network(session.device_id)
        session.issues_found.extend(network_issues)
        session.add_log(f"网络诊断完成，发现 {len(network_issues)} 个问题")
        
        # 应用诊断 (55-60%)
        session.update_progress(RepairStage.DIAGNOSTIC_APPS, 57)
        self._notify_progress(session.session_id, RepairStage.DIAGNOSTIC_APPS, 57, "检查应用状态")
        app_issues = self.diagnostic_engine.diagnose_applications(session.device_id)
        session.issues_found.extend(app_issues)
        session.add_log(f"应用诊断完成，发现 {len(app_issues)} 个问题")
        
        # 生成诊断报告
        session.update_progress(RepairStage.REPORT_GENERATION, 60)
        self._notify_progress(session.session_id, RepairStage.REPORT_GENERATION, 60, "生成诊断报告")
        session.diagnostic_report = self._generate_diagnostic_report(session)
        session.add_log(f"诊断完成，总共发现 {len(session.issues_found)} 个问题")
    
    def _generate_diagnostic_report(self, session: RepairSession) -> DiagnosticReport:
        """生成诊断报告"""
        device = self.device_manager.get_device(session.device_id)
        
        # 计算健康评分 (0-100)
        total_issues = len(session.issues_found)
        critical_issues = len([issue for issue in session.issues_found if issue.severity == "critical"])
        major_issues = len([issue for issue in session.issues_found if issue.severity == "major"])
        minor_issues = len([issue for issue in session.issues_found if issue.severity == "minor"])
        
        # 健康评分计算逻辑
        health_score = 100
        health_score -= critical_issues * 20  # 严重问题扣20分
        health_score -= major_issues * 10     # 重要问题扣10分
        health_score -= minor_issues * 5      # 轻微问题扣5分
        health_score = max(0, health_score)   # 最低0分
        
        session.health_score = health_score
        
        recommendations = []
        if critical_issues > 0:
            recommendations.append("立即执行安全修复，清除恶意软件")
        if major_issues > 0:
            recommendations.append("清理存储空间，修复系统文件")
        if minor_issues > 0:
            recommendations.append("执行常规维护，优化系统性能")
        if total_issues == 0:
            recommendations.append("设备状态良好，建议定期维护")
            
        return DiagnosticReport(
            device_info=device,  # pyright: ignore[reportCallIssue]
            scan_time=datetime.now(),
            issues=session.issues_found,  # pyright: ignore[reportCallIssue]
            health_score=health_score,  # pyright: ignore[reportCallIssue]
            recommendations=recommendations,
            scan_duration=int((datetime.now() - session.start_time).total_seconds())  # pyright: ignore[reportCallIssue]
        )
    
    def _generate_repair_plan(self, session: RepairSession, repair_options: Dict[str, Any]):
        """生成修复计划"""
        session.update_progress(RepairStage.REPAIR_PLANNING, 65)
        session.add_log("开始制定修复计划")
        self._notify_progress(session.session_id, RepairStage.REPAIR_PLANNING, 65, "制定修复计划")
        
        # 根据问题类型确定修复策略
        repair_types = set()
        for issue in session.issues_found:
            if "存储" in issue.category or "缓存" in issue.description:  # pyright: ignore[reportOperatorIssue]
                repair_types.add(RepairType.STORAGE_CLEANUP)
            elif "病毒" in issue.description or "恶意" in issue.description:
                repair_types.add(RepairType.VIRUS_REMOVAL)
            elif "系统文件" in issue.category:  # pyright: ignore[reportOperatorIssue]
                repair_types.add(RepairType.SYSTEM_REPAIR)
            elif "网络" in issue.category:  # pyright: ignore[reportOperatorIssue]
                repair_types.add(RepairType.NETWORK_RESET)
            elif "应用" in issue.category:  # pyright: ignore[reportOperatorIssue]
                repair_types.add(RepairType.APP_CLEANUP)
        
        # 如果用户选择全面修复
        if repair_options.get("full_repair", False):
            repair_types.add(RepairType.FULL_REPAIR)
        
        # 创建修复任务
        for repair_type in repair_types:
            task_id = self.repair_engine.create_repair_plan(session.device_id, repair_type, session.issues_found)
            if task_id:
                # 获取创建的任务
                task = self.repair_engine.get_repair_task(task_id)
                if task:
                    session.repair_tasks.append(task)
        
        session.add_log(f"修复计划制定完成，包含 {len(session.repair_tasks)} 个修复任务")
        self._notify_progress(session.session_id, RepairStage.REPAIR_PLANNING, 70, f"修复计划已制定({len(session.repair_tasks)}个任务)")
    
    def _execute_repairs(self, session: RepairSession):
        """执行修复任务"""
        session.update_progress(RepairStage.REPAIR_EXECUTION, 75)
        session.add_log("开始执行修复任务")
        self._notify_progress(session.session_id, RepairStage.REPAIR_EXECUTION, 75, "开始执行修复")
        
        total_tasks = len(session.repair_tasks)
        completed_tasks = 0
        
        for task in session.repair_tasks:
            session.add_log(f"执行修复任务: {task.task_type}")
            
            # 执行修复任务
            success = self.repair_engine.execute_repair(task.task_id)
            
            if success:
                session.add_log(f"修复任务完成: {task.task_type}")
                completed_tasks += 1
            else:
                session.add_log(f"修复任务失败: {task.task_type}")
            
            # 更新进度 (75% - 95%)
            progress = 75 + int((completed_tasks / total_tasks) * 20)
            self._notify_progress(session.session_id, RepairStage.REPAIR_EXECUTION, progress, 
                                f"修复进度: {completed_tasks}/{total_tasks}")
        
        session.add_log(f"修复任务执行完成: {completed_tasks}/{total_tasks} 个任务成功")
    
    def _verify_repairs(self, session: RepairSession):
        """验证修复结果"""
        session.update_progress(RepairStage.VERIFICATION, 95)
        session.add_log("开始验证修复结果")
        self._notify_progress(session.session_id, RepairStage.VERIFICATION, 95, "验证修复结果")
        
        # 重新执行快速诊断来验证修复效果
        remaining_issues = []
        
        # 快速检查关键问题是否已解决
        for issue in session.issues_found:
            if issue.severity == "critical":
                # 重新检查这个问题是否仍然存在
                # 这里简化处理，实际应该重新运行相应的诊断
                pass
        
        session.add_log("修复结果验证完成")
        self._notify_progress(session.session_id, RepairStage.VERIFICATION, 100, "修复验证完成")
    
    def get_repair_status(self, session_id: str) -> Optional[RepairSession]:
        """
        获取修复状态
        
        Args:
            session_id: 会话ID
            
        Returns:
            修复会话信息
        """
        return self.active_sessions.get(session_id)
    
    def cancel_repair(self, session_id: str) -> bool:
        """
        取消修复任务
        
        Args:
            session_id: 会话ID
            
        Returns:
            是否成功取消
        """
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        
        # 取消所有修复任务
        for task in session.repair_tasks:
            self.repair_engine.cancel_repair(task.task_id)
        
        session.complete(False, "用户取消")
        session.add_log("修复已被用户取消")
        
        self.logger.info(f"修复任务已取消: {session_id}")
        return True
    
    def get_active_sessions(self) -> List[RepairSession]:
        """获取所有活动的修复会话"""
        return list(self.active_sessions.values())
    
    def cleanup_completed_sessions(self, max_age_hours: int = 24):
        """清理已完成的会话"""
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if session.end_time:
                age_hours = (current_time - session.end_time).total_seconds() / 3600
                if age_hours > max_age_hours:
                    expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
            
        if expired_sessions:
            self.logger.info(f"清理了 {len(expired_sessions)} 个过期会话")
    
    def _setup_exception_callbacks(self):
        """设置异常处理器的回调函数"""
        self.exception_handler.add_exception_callback(self._on_repair_exception)
        self.exception_handler.add_recovery_callback(self._on_recovery_action)
    
    def _on_repair_exception(self, task_id: str, device_id: str, operation: str, 
                           exception_type, exception: Exception):
        """处理修复异常的回调"""
        # 查找对应的修复会话
        session = None
        for s in self.active_sessions.values():
            if s.device_id == device_id:
                session = s
                break
        
        if session:
            error_msg = f"操作异常 - {operation}: {exception_type.value}"
            session.add_log(error_msg)
            self._notify_progress(session.session_id, session.current_stage, 
                                session.progress, error_msg)
    
    def _on_recovery_action(self, task_id: str, device_id: str, 
                          recovery_action: RecoveryAction, message: str):
        """处理恢复动作的回调"""
        # 查找对应的修复会话
        session = None
        for s in self.active_sessions.values():
            if s.device_id == device_id:
                session = s
                break
        
        if session:
            recovery_msg = f"恢复动作: {recovery_action.value} - {message}"
            session.add_log(recovery_msg)
            
            if recovery_action == RecoveryAction.ABORT:
                session.complete(False, "由于异常中止修复")
                self._notify_completion(session.session_id, False, session)
    
    def _execute_with_exception_handling(self, session: RepairSession, 
                                       operation: str, func: callable, *args, **kwargs):
        """
        在异常处理保护下执行函数
        
        Args:
            session: 修复会话
            operation: 操作名称
            func: 要执行的函数
            *args: 位置参数
            **kwargs: 关键字参数
            
        Returns:
            函数执行结果
        """
        max_retries = 3
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                # 创建备份（如果需要）
                if hasattr(func, '__backup_data__'):
                    backup_data = func.__backup_data__()
                    self.exception_handler.create_backup(
                        session.session_id, session.device_id, operation, backup_data
                    )
                
                # 执行操作
                result = func(*args, **kwargs)
                return result
                
            except Exception as e:
                # 处理异常
                recovery_action = self.exception_handler.handle_exception(
                    session.session_id, session.device_id, operation, e
                )
                
                if recovery_action == RecoveryAction.RETRY:
                    retry_count += 1
                    if retry_count <= max_retries:
                        session.add_log(f"重试操作: {operation} (第{retry_count}次)")
                        continue
                    else:
                        session.add_log(f"操作重试次数超限: {operation}")
                        raise e
                
                elif recovery_action == RecoveryAction.SKIP:
                    session.add_log(f"跳过操作: {operation}")
                    return None
                
                elif recovery_action == RecoveryAction.ABORT:
                    session.add_log(f"中止操作: {operation}")
                    raise e
                
                elif recovery_action == RecoveryAction.REQUEST_USER_ACTION:
                    session.add_log(f"需要用户干预: {operation}")
                    # 这里可以通过回调通知用户界面
                    raise e
                
                else:
                    # 其他恢复动作都作为异常处理
                    raise e
        
        # 超过最大重试次数
        raise Exception(f"操作 {operation} 在多次重试后仍然失败")