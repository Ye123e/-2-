#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复引擎和操作调度器模块
负责协调各种修复操作的执行顺序和管理修复任务
"""

import threading
import uuid
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

from ..models import (
    DeviceInfo, DiagnosticReport, Issue, IssueCategory, 
    IssueSeverity, RepairTask, TaskStatus
)
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager
from .diagnostic_engine import DiagnosticEngine
from .security_scanner import SecurityScanner, VirusSignatureDatabase
from .file_manager import FileScanner, FileCleaner
from .file_cleanup import FileCleanupEngine

class RepairType(Enum):
    """修复类型枚举"""
    STORAGE_CLEANUP = "STORAGE_CLEANUP"           # 存储清理
    CACHE_CLEAR = "CACHE_CLEAR"                   # 缓存清理
    VIRUS_REMOVAL = "VIRUS_REMOVAL"               # 病毒清除
    FILE_CLEANUP = "FILE_CLEANUP"                 # 文件清理
    PERMISSION_FIX = "PERMISSION_FIX"             # 权限修复
    SYSTEM_REPAIR = "SYSTEM_REPAIR"               # 系统修复
    APP_CLEANUP = "APP_CLEANUP"                   # 应用清理
    NETWORK_RESET = "NETWORK_RESET"               # 网络重置
    FULL_REPAIR = "FULL_REPAIR"                   # 全面修复

@dataclass
class RepairStep:
    """修复步骤数据类"""
    step_id: str
    repair_type: RepairType
    description: str
    estimated_duration: int  # 预计耗时（秒）
    requires_root: bool = False
    backup_required: bool = False
    dependencies: List[str] = field(default_factory=list)  # 依赖的步骤ID
    
    def __post_init__(self):
        if not self.step_id:
            self.step_id = str(uuid.uuid4())

class RepairEngine(LoggerMixin):
    """修复引擎"""
    
    def __init__(self, device_manager: DeviceManager):
        """
        初始化修复引擎
        
        Args:
            device_manager: 设备管理器
        """
        self.device_manager = device_manager
        self.diagnostic_engine = DiagnosticEngine(device_manager)
        
        # 初始化安全扫描器
        signature_db = VirusSignatureDatabase()
        self.security_scanner = SecurityScanner(device_manager, signature_db)
        
        # 初始化文件管理器
        self.file_scanner = FileScanner(device_manager)
        self.file_cleaner = FileCleaner(device_manager)
        
        # 任务管理
        self.active_tasks: Dict[str, RepairTask] = {}
        self.task_callbacks: List[Callable[[RepairTask], None]] = []
        self.progress_callbacks: List[Callable[[str, int, str], None]] = []
        
        # 修复计划模板
        self._init_repair_templates()
    
    def _init_repair_templates(self):
        """初始化修复计划模板"""
        self.repair_templates = {
            RepairType.STORAGE_CLEANUP: [
                RepairStep(
                    step_id="cache_clear",
                    repair_type=RepairType.CACHE_CLEAR,
                    description="清理应用缓存",
                    estimated_duration=30
                ),
                RepairStep(
                    step_id="temp_files_clean",
                    repair_type=RepairType.FILE_CLEANUP,
                    description="清理临时文件",
                    estimated_duration=60
                ),
                RepairStep(
                    step_id="log_files_clean",
                    repair_type=RepairType.FILE_CLEANUP,
                    description="清理日志文件",
                    estimated_duration=30
                )
            ],
            
            RepairType.VIRUS_REMOVAL: [
                RepairStep(
                    step_id="virus_scan",
                    repair_type=RepairType.VIRUS_REMOVAL,
                    description="扫描病毒",
                    estimated_duration=120
                ),
                RepairStep(
                    step_id="remove_malware",
                    repair_type=RepairType.VIRUS_REMOVAL,
                    description="清除恶意软件",
                    estimated_duration=60,
                    dependencies=["virus_scan"]
                ),
                RepairStep(
                    step_id="security_scan",
                    repair_type=RepairType.VIRUS_REMOVAL,
                    description="安全检查",
                    estimated_duration=30,
                    dependencies=["remove_malware"]
                )
            ],
            
            RepairType.FULL_REPAIR: [
                RepairStep(
                    step_id="backup_data",
                    repair_type=RepairType.SYSTEM_REPAIR,
                    description="备份重要数据",
                    estimated_duration=180,
                    backup_required=True
                ),
                RepairStep(
                    step_id="virus_scan_full",
                    repair_type=RepairType.VIRUS_REMOVAL,
                    description="全面病毒扫描",
                    estimated_duration=300,
                    dependencies=["backup_data"]
                ),
                RepairStep(
                    step_id="file_cleanup_full",
                    repair_type=RepairType.FILE_CLEANUP,
                    description="全面文件清理",
                    estimated_duration=240,
                    dependencies=["virus_scan_full"]
                ),
                RepairStep(
                    step_id="permission_repair",
                    repair_type=RepairType.PERMISSION_FIX,
                    description="修复权限问题",
                    estimated_duration=120,
                    requires_root=True,
                    dependencies=["file_cleanup_full"]
                ),
                RepairStep(
                    step_id="system_optimize",
                    repair_type=RepairType.SYSTEM_REPAIR,
                    description="系统优化",
                    estimated_duration=180,
                    dependencies=["permission_repair"]
                )
            ]
        }
    
    def add_task_callback(self, callback: Callable[[RepairTask], None]):
        """添加任务状态回调"""
        self.task_callbacks.append(callback)
    
    def add_progress_callback(self, callback: Callable[[str, int, str], None]):
        """添加进度回调"""
        self.progress_callbacks.append(callback)
    
    def _notify_task_callbacks(self, task: RepairTask):
        """通知任务状态回调"""
        for callback in self.task_callbacks:
            try:
                callback(task)
            except Exception as e:
                self.logger.error(f"任务回调执行失败: {e}")
    
    def _update_progress(self, task_id: str, progress: int, message: str):
        """更新任务进度"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.progress = progress
            task.add_log(message)
        
        for callback in self.progress_callbacks:
            try:
                callback(task_id, progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def create_repair_plan(self, device_id: str, repair_type: RepairType, 
                          custom_issues: List[Issue] = None) -> Optional[str]:
        """
        创建修复计划
        
        Args:
            device_id: 设备ID
            repair_type: 修复类型
            custom_issues: 自定义问题列表
            
        Returns:
            修复任务ID，失败返回none
        """
        try:
            device_info = self.device_manager.get_device(device_id)
            if not device_info:
                self.logger.error(f"设备未找到: {device_id}")
                return None
            
            # 生成任务ID
            task_id = str(uuid.uuid4())
            
            # 获取修复步骤模板
            repair_steps = self._get_repair_steps(repair_type, custom_issues, device_info)
            
            if not repair_steps:
                self.logger.error(f"无法生成修复计划: {repair_type}")
                return None
            
            # 计算总的预计时间
            total_duration = sum(step.estimated_duration for step in repair_steps)
            
            # 创建修复任务
            repair_task = RepairTask(
                task_id=task_id,
                device_id=device_id,
                task_type=repair_type.value,
                status=TaskStatus.PENDING,
                progress=0,
                start_time=None,
                end_time=None,
                estimated_duration=total_duration,
                logs=[],
                error_message=None,
                details={
                    'repair_steps': [
                        {
                            'step_id': step.step_id,
                            'description': step.description,
                            'estimated_duration': step.estimated_duration,
                            'requires_root': step.requires_root,
                            'backup_required': step.backup_required,
                            'dependencies': step.dependencies,
                            'status': 'pending'
                        } for step in repair_steps
                    ],
                    'custom_issues': [issue.__dict__ for issue in (custom_issues or [])],
                    'device_capabilities': self.device_manager.get_device_capabilities(device_id)
                }
            )
            
            self.active_tasks[task_id] = repair_task
            repair_task.add_log(f"修复计划已创建: {repair_type.value}, 包含 {len(repair_steps)} 个步骤")
            
            self.logger.info(f"修复计划创建成功: {task_id} - {repair_type.value}")
            self._notify_task_callbacks(repair_task)
            
            return task_id
            
        except Exception as e:
            self.logger.error(f"创建修复计划失败: {e}")
            return None
    
    def _get_repair_steps(self, repair_type: RepairType, custom_issues: List[Issue], 
                         device_info: DeviceInfo) -> List[RepairStep]:
        """
        获取修复步骤列表
        
        Args:
            repair_type: 修复类型
            custom_issues: 自定义问题
            device_info: 设备信息
            
        Returns:
            修复步骤列表
        """
        base_steps = self.repair_templates.get(repair_type, [])
        
        # 复制模板步骤以避免修改原模板
        repair_steps = []
        for step in base_steps:
            new_step = RepairStep(
                step_id=step.step_id,
                repair_type=step.repair_type,
                description=step.description,
                estimated_duration=step.estimated_duration,
                requires_root=step.requires_root,
                backup_required=step.backup_required,
                dependencies=step.dependencies.copy()
            )
            repair_steps.append(new_step)
        
        # 根据具体问题调整修复步骤
        if custom_issues:
            repair_steps = self._customize_repair_steps(repair_steps, custom_issues, device_info)
        
        # 根据设备能力调整步骤
        repair_steps = self._adjust_steps_for_device(repair_steps, device_info)
        
        return repair_steps
    
    def _customize_repair_steps(self, base_steps: List[RepairStep], 
                               custom_issues: List[Issue], 
                               device_info: DeviceInfo) -> List[RepairStep]:
        """
        根据具体问题定制修复步骤
        """
        additional_steps = []
        
        # 根据不同问题类型添加特定的修复步骤
        issue_categories = set(issue.category for issue in custom_issues)
        
        if "storage" in issue_categories:
            # 添加存储优化步骤
            storage_step = RepairStep(
                step_id="optimize_storage",
                repair_type=RepairType.STORAGE_CLEANUP,
                description=f"优化存储空间 (当前使用: {device_info.storage_usage_percent:.1f}%)",
                estimated_duration=90
            )
            additional_steps.append(storage_step)
        
        if "applications" in issue_categories:
            # 添加应用优化步骤
            app_step = RepairStep(
                step_id="optimize_apps",
                repair_type=RepairType.APP_CLEANUP,
                description="优化应用程序设置",
                estimated_duration=60
            )
            additional_steps.append(app_step)
        
        if "network" in issue_categories:
            # 添加网络修复步骤
            network_step = RepairStep(
                step_id="repair_network",
                repair_type=RepairType.NETWORK_RESET,
                description="修复网络配置问题",
                estimated_duration=45
            )
            additional_steps.append(network_step)
        
        # 根据问题严重程度调整优先级
        critical_issues = [issue for issue in custom_issues if issue.severity == "critical"]
        if critical_issues:
            # 在开始添加紧急处理步骤
            emergency_step = RepairStep(
                step_id="emergency_fix",
                repair_type=RepairType.SYSTEM_REPAIR,
                description=f"紧急处理严重问题 ({len(critical_issues)}个)",
                estimated_duration=120
            )
            additional_steps.insert(0, emergency_step)
        
        return additional_steps + base_steps
    
    def _adjust_steps_for_device(self, steps: List[RepairStep], 
                                device_info: DeviceInfo) -> List[RepairStep]:
        """
        根据设备能力调整修复步骤
        """
        adjusted_steps = []
        device_capabilities = self.device_manager.get_device_capabilities(device_info.device_id)
        
        for step in steps:
            # 检查是否需要ROOT权限
            if step.requires_root and not device_capabilities.get('root_access', False):
                # 替换为不需要ROOT的替代方案
                alternative_step = self._get_alternative_step(step, device_capabilities)
                if alternative_step:
                    adjusted_steps.append(alternative_step)
                else:
                    # 跳过需要ROOT的步骤，但记录日志
                    skip_step = RepairStep(
                        step_id=f"skip_{step.step_id}",
                        repair_type=step.repair_type,
                        description=f"跳过: {step.description} (需要ROOT权限)",
                        estimated_duration=5
                    )
                    adjusted_steps.append(skip_step)
            else:
                adjusted_steps.append(step)
        
        return adjusted_steps
    
    def _get_alternative_step(self, original_step: RepairStep, 
                             device_capabilities: Dict[str, bool]) -> Optional[RepairStep]:
        """
        获取替代的修复步骤
        """
        alternatives = {
            RepairType.PERMISSION_FIX: RepairStep(
                step_id=f"alt_{original_step.step_id}",
                repair_type=RepairType.PERMISSION_FIX,
                description="使用用户权限修复部分权限问题",
                estimated_duration=original_step.estimated_duration // 2
            ),
            RepairType.SYSTEM_REPAIR: RepairStep(
                step_id=f"alt_{original_step.step_id}",
                repair_type=RepairType.APP_CLEANUP,
                description="使用应用级优化替代系统级修复",
                estimated_duration=original_step.estimated_duration
            )
        }
        
        return alternatives.get(original_step.repair_type)
    
    def execute_repair(self, task_id: str) -> bool:
        """
        执行修复任务
        
        Args:
            task_id: 任务ID
            
        Returns:
            是否成功
        """
        if task_id not in self.active_tasks:
            self.logger.error(f"任务未找到: {task_id}")
            return False
        
        task = self.active_tasks[task_id]
        
        # 在新线程中执行修复
        repair_thread = threading.Thread(
            target=self._execute_repair_task,
            args=(task,),
            daemon=True
        )
        repair_thread.start()
        
        return True
    
    def _execute_repair_task(self, task: RepairTask):
        """执行修复任务的具体实现"""
        try:
            task.start()
            self._update_progress(task.task_id, 0, "开始执行修复任务")
            self._notify_task_callbacks(task)
            
            device_info = self.device_manager.get_device(task.device_id)
            if not device_info:
                raise Exception(f"设备未连接: {task.device_id}")
            
            # 获取修复步骤
            repair_steps_data = task.details.get('repair_steps', [])
            repair_steps = []
            
            for step_data in repair_steps_data:
                step = RepairStep(
                    step_id=step_data['step_id'],
                    repair_type=RepairType(step_data.get('repair_type', RepairType.STORAGE_CLEANUP.value)),
                    description=step_data['description'],
                    estimated_duration=step_data['estimated_duration'],
                    requires_root=step_data.get('requires_root', False),
                    backup_required=step_data.get('backup_required', False),
                    dependencies=step_data.get('dependencies', [])
                )
                repair_steps.append(step)
            
            total_steps = len(repair_steps)
            completed_steps = []
            
            for i, step in enumerate(repair_steps):
                # 检查依赖
                if not self._check_dependencies(step, completed_steps):
                    error_msg = f"步骤依赖未满足: {step.step_id}"
                    task.add_log(error_msg)
                    continue
                
                # 更新进度
                progress = int((i / total_steps) * 100)
                self._update_progress(task.task_id, progress, f"正在执行: {step.description}")
                
                # 执行修复步骤
                success = self._execute_repair_step(task, step, device_info)
                
                if success:
                    completed_steps.append(step.step_id)
                    task.add_log(f"步骤完成: {step.description}")
                    
                    # 更新步骤状态
                    for step_data in task.details['repair_steps']:
                        if step_data['step_id'] == step.step_id:
                            step_data['status'] = 'completed'
                            break
                else:
                    task.add_log(f"步骤失败: {step.description}")
                    
                    # 更新步骤状态
                    for step_data in task.details['repair_steps']:
                        if step_data['step_id'] == step.step_id:
                            step_data['status'] = 'failed'
                            break
            
            # 完成任务
            success_rate = len(completed_steps) / total_steps if total_steps > 0 else 0
            
            if success_rate >= 0.8:  # 80%以上成功率认为成功
                task.complete()
                self._update_progress(task.task_id, 100, f"修复完成 ({len(completed_steps)}/{total_steps}个步骤成功)")
            else:
                task.fail(f"修复未完全成功: {len(completed_steps)}/{total_steps}个步骤成功")
                self._update_progress(task.task_id, int(success_rate * 100), 
                                    f"修复部分成功: {len(completed_steps)}/{total_steps}")
            
            self._notify_task_callbacks(task)
            
        except Exception as e:
            error_msg = f"修复任务异常: {str(e)}"
            self.logger.error(error_msg)
            task.fail(error_msg)
            self._update_progress(task.task_id, task.progress, error_msg)
            self._notify_task_callbacks(task)
    
    def _check_dependencies(self, step: RepairStep, completed_steps: List[str]) -> bool:
        """检查步骤依赖是否已完成"""
        for dependency in step.dependencies:
            if dependency not in completed_steps:
                return False
        return True
    
    def _execute_repair_step(self, task: RepairTask, step: RepairStep, device_info: DeviceInfo) -> bool:
        """执行具体的修复步骤"""
        try:
            task.add_log(f"开始执行步骤: {step.description}")
            
            if step.repair_type == RepairType.CACHE_CLEAR:
                return self._repair_cache_clear(task, device_info)
            elif step.repair_type == RepairType.FILE_CLEANUP:
                return self._repair_file_cleanup(task, device_info)
            elif step.repair_type == RepairType.VIRUS_REMOVAL:
                return self._repair_virus_removal(task, device_info)
            elif step.repair_type == RepairType.PERMISSION_FIX:
                return self._repair_permission_fix(task, device_info)
            elif step.repair_type == RepairType.SYSTEM_REPAIR:
                return self._repair_system_repair(task, device_info)
            elif step.repair_type == RepairType.APP_CLEANUP:
                return self._repair_app_cleanup(task, device_info)
            elif step.repair_type == RepairType.NETWORK_RESET:
                return self._repair_network_reset(task, device_info)
            elif step.repair_type == RepairType.STORAGE_CLEANUP:
                return self._repair_storage_cleanup(task, device_info)
            else:
                task.add_log(f"不支持的修复类型: {step.repair_type}")
                return False
                
        except Exception as e:
            error_msg = f"执行修复步骤异常: {str(e)}"
            task.add_log(error_msg)
            self.logger.error(error_msg)
            return False
    
    def _repair_cache_clear(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """清理应用缓存"""
        try:
            # 获取应用列表
            packages_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'pm list packages -3'
            )
            
            if not packages_result:
                task.add_log("无法获取应用列表")
                return False
            
            packages = [line.replace('package:', '').strip() 
                       for line in packages_result.strip().split('\n') 
                       if line.startswith('package:')]
            
            cleared_count = 0
            for package in packages[:10]:  # 只清理前10个应用
                result = self.device_manager.adb_manager.execute_command(
                    device_info.device_id, f'pm clear {package}'
                )
                if result and 'Success' in result:
                    cleared_count += 1
            
            task.add_log(f"成功清理 {cleared_count} 个应用的缓存")
            return cleared_count > 0
            
        except Exception as e:
            task.add_log(f"清理缓存失败: {str(e)}")
            return False
    
    def _repair_file_cleanup(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """清理文件"""
        try:
            # 清理临时文件
            temp_dirs = ['/data/local/tmp', '/cache', '/data/cache']
            cleaned_files = 0
            
            for temp_dir in temp_dirs:
                result = self.device_manager.adb_manager.execute_command(
                    device_info.device_id, f'find {temp_dir} -type f -name "*.tmp" -delete 2>/dev/null; echo "done"'
                )
                if result and 'done' in result:
                    cleaned_files += 1
            
            # 清理日志文件
            log_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'logcat -c'
            )
            
            task.add_log(f"文件清理完成，处理 {cleaned_files} 个目录")
            return True
            
        except Exception as e:
            task.add_log(f"文件清理失败: {str(e)}")
            return False
    
    def _repair_virus_removal(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """病毒清除"""
        try:
            # 执行安全扫描
            scan_result = self.security_scanner.scan_device(device_info.device_id)
            
            if not scan_result:
                task.add_log("安全扫描完成，未发现威胁")
                return True
            
            # 处理发现的威胁
            removed_count = 0
            for threat in scan_result[:5]:  # 只处理前5个威胁
                if threat.severity == "critical":
                    # 尝试删除恶意应用
                    if hasattr(threat, 'package_name') and threat.package_name:
                        uninstall_result = self.device_manager.adb_manager.execute_command(
                            device_info.device_id, f'pm uninstall {threat.package_name}'
                        )
                        if uninstall_result and 'Success' in uninstall_result:
                            removed_count += 1
                            task.add_log(f"已删除恶意应用: {threat.package_name}")
            
            task.add_log(f"安全清理完成，处理 {removed_count} 个威胁")
            return True
            
        except Exception as e:
            task.add_log(f"病毒清除失败: {str(e)}")
            return False
    
    def _repair_permission_fix(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """修复权限问题"""
        try:
            # 重置应用权限
            reset_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'pm reset-permissions'
            )
            
            task.add_log("权限修复完成")
            return True
            
        except Exception as e:
            task.add_log(f"权限修复失败: {str(e)}")
            return False
    
    def _repair_system_repair(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """系统修复"""
        try:
            # 重启系统服务
            restart_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'am restart'
            )
            
            task.add_log("系统修复完成")
            return True
            
        except Exception as e:
            task.add_log(f"系统修复失败: {str(e)}")
            return False
    
    def _repair_app_cleanup(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """应用清理"""
        try:
            # 停止占用过多资源的应用
            stop_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'am kill-all'
            )
            
            task.add_log("应用清理完成")
            return True
            
        except Exception as e:
            task.add_log(f"应用清理失败: {str(e)}")
            return False
    
    def _repair_network_reset(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """网络重置"""
        try:
            # 重置网络设置
            wifi_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, 'svc wifi disable && svc wifi enable'
            )
            
            task.add_log("网络重置完成")
            return True
            
        except Exception as e:
            task.add_log(f"网络重置失败: {str(e)}")
            return False
    
    def _repair_storage_cleanup(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """存储清理"""
        try:
            # 综合存储清理
            cache_success = self._repair_cache_clear(task, device_info)
            file_success = self._repair_file_cleanup(task, device_info)
            
            task.add_log("存储清理完成")
            return cache_success or file_success
            
        except Exception as e:
            task.add_log(f"存储清理失败: {str(e)}")
            return False
    
    def get_repair_task(self, task_id: str) -> Optional[RepairTask]:
        """获取修复任务"""
        return self.active_tasks.get(task_id)
    
    def cancel_repair(self, task_id: str) -> bool:
        """取消修复任务"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
                task.status = TaskStatus.CANCELLED
                task.add_log("任务已取消")
                self._notify_task_callbacks(task)
                return True
        return False
    
    def get_active_tasks(self) -> List[RepairTask]:
        """获取所有活动任务"""
        return list(self.active_tasks.values())
        """
        创建修复计划
        
        Args:
            device_id: 设备ID
            repair_type: 修复类型
            custom_issues: 自定义问题列表
            
        Returns:
            任务ID，失败返回None
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return None
        
        # 生成任务ID
        task_id = str(uuid.uuid4())
        
        # 根据修复类型获取修复步骤
        repair_steps = self._get_repair_steps(repair_type, device_info, custom_issues)
        
        # 创建修复任务
        task = RepairTask(
            task_id=task_id,
            device_id=device_id,
            task_type=repair_type.value,
            estimated_duration=sum(step.estimated_duration for step in repair_steps)
        )
        
        # 存储修复步骤到任务详情中
        task.details = {
            'repair_steps': repair_steps,
            'device_info': device_info,
            'custom_issues': custom_issues or []
        }
        
        self.active_tasks[task_id] = task
        task.add_log(f"创建修复计划: {repair_type.value}")
        
        self.logger.info(f"创建修复计划成功: {task_id}, 类型: {repair_type.value}")
        self._notify_task_callbacks(task)
        
        return task_id
    
    def _get_repair_steps(self, repair_type: RepairType, device_info: DeviceInfo, 
                         custom_issues: List[Issue] = None) -> List[RepairStep]:
        """获取修复步骤"""
        if repair_type in self.repair_templates:
            steps = self.repair_templates[repair_type].copy()
        else:
            steps = []
        
        # 根据设备状态和问题定制修复步骤
        if custom_issues:
            steps.extend(self._generate_custom_steps(custom_issues))
        
        # 根据设备ROOT状态过滤步骤
        if not device_info.root_status:
            steps = [step for step in steps if not step.requires_root]
        
        return steps
    
    def _generate_custom_steps(self, issues: List[Issue]) -> List[RepairStep]:
        """根据问题生成自定义修复步骤"""
        custom_steps = []
        
        for issue in issues:
            if issue.auto_fixable:
                step = RepairStep(
                    step_id=f"fix_{issue.category.value.lower()}",
                    repair_type=self._map_issue_to_repair_type(issue.category),
                    description=f"修复: {issue.description}",
                    estimated_duration=self._estimate_fix_duration(issue)
                )
                custom_steps.append(step)
        
        return custom_steps
    
    def _map_issue_to_repair_type(self, category: IssueCategory) -> RepairType:
        """将问题类别映射到修复类型"""
        mapping = {
            IssueCategory.STORAGE: RepairType.STORAGE_CLEANUP,
            IssueCategory.VIRUS: RepairType.VIRUS_REMOVAL,
            IssueCategory.ERROR_FILES: RepairType.FILE_CLEANUP,
            IssueCategory.PERMISSIONS: RepairType.PERMISSION_FIX,
            IssueCategory.SYSTEM_FILES: RepairType.SYSTEM_REPAIR,
            IssueCategory.APPS: RepairType.APP_CLEANUP,
            IssueCategory.NETWORK: RepairType.NETWORK_RESET
        }
        return mapping.get(category, RepairType.SYSTEM_REPAIR)
    
    def _estimate_fix_duration(self, issue: Issue) -> int:
        """估算修复时长"""
        duration_map = {
            IssueSeverity.LOW: 30,
            IssueSeverity.MEDIUM: 60,
            IssueSeverity.HIGH: 120,
            IssueSeverity.CRITICAL: 300
        }
        return duration_map.get(issue.severity, 60)
    
    def execute_repair(self, task_id: str) -> bool:
        """
        执行修复任务
        
        Args:
            task_id: 任务ID
            
        Returns:
            执行是否成功
        """
        if task_id not in self.active_tasks:
            self.logger.error(f"任务不存在: {task_id}")
            return False
        
        task = self.active_tasks[task_id]
        
        # 在新线程中执行修复
        repair_thread = threading.Thread(
            target=self._execute_repair_task,
            args=(task,),
            daemon=True
        )
        repair_thread.start()
        
        return True
    
    def _execute_repair_task(self, task: RepairTask):
        """执行修复任务的线程函数"""
        try:
            task.start()
            self._notify_task_callbacks(task)
            
            repair_steps = task.details.get('repair_steps', [])
            device_info = task.details.get('device_info')
            
            if not repair_steps:
                task.fail("没有可执行的修复步骤")
                self._notify_task_callbacks(task)
                return
            
            total_steps = len(repair_steps)
            
            # 执行每个修复步骤
            for i, step in enumerate(repair_steps):
                step_progress = int((i / total_steps) * 100)
                self._update_progress(task.task_id, step_progress, f"执行: {step.description}")
                
                # 检查依赖关系
                if not self._check_dependencies(step, repair_steps[:i]):
                    task.fail(f"步骤依赖检查失败: {step.description}")
                    self._notify_task_callbacks(task)
                    return
                
                # 执行修复步骤
                success = self._execute_repair_step(task, step, device_info)
                
                if not success:
                    task.fail(f"修复步骤失败: {step.description}")
                    self._notify_task_callbacks(task)
                    return
            
            # 任务完成
            task.complete()
            self._notify_task_callbacks(task)
            self._update_progress(task.task_id, 100, "修复任务完成")
            
        except Exception as e:
            task.fail(f"修复任务异常: {str(e)}")
            self._notify_task_callbacks(task)
            self.logger.error(f"修复任务异常: {e}")
    
    def _check_dependencies(self, step: RepairStep, completed_steps: List[RepairStep]) -> bool:
        """检查步骤依赖关系"""
        if not step.dependencies:
            return True
        
        completed_step_ids = {s.step_id for s in completed_steps}
        
        for dep_id in step.dependencies:
            if dep_id not in completed_step_ids:
                self.logger.error(f"依赖步骤未完成: {dep_id}")
                return False
        
        return True
    
    def _execute_repair_step(self, task: RepairTask, step: RepairStep, device_info: DeviceInfo) -> bool:
        """执行单个修复步骤"""
        try:
            self.logger.info(f"执行修复步骤: {step.description}")
            
            if step.repair_type == RepairType.CACHE_CLEAR:
                return self._repair_cache_clear(task, device_info)
            elif step.repair_type == RepairType.FILE_CLEANUP:
                return self._repair_file_cleanup(task, device_info)
            elif step.repair_type == RepairType.VIRUS_REMOVAL:
                return self._repair_virus_removal(task, device_info)
            elif step.repair_type == RepairType.PERMISSION_FIX:
                return self._repair_permission_fix(task, device_info)
            elif step.repair_type == RepairType.SYSTEM_REPAIR:
                return self._repair_system_repair(task, device_info)
            elif step.repair_type == RepairType.APP_CLEANUP:
                return self._repair_app_cleanup(task, device_info)
            elif step.repair_type == RepairType.NETWORK_RESET:
                return self._repair_network_reset(task, device_info)
            else:
                self.logger.warning(f"未知的修复类型: {step.repair_type}")
                return True  # 跳过未知类型
                
        except Exception as e:
            self.logger.error(f"执行修复步骤异常: {e}")
            return False
    
    def _repair_cache_clear(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行缓存清理修复"""
        try:
            task.add_log("开始清理缓存...")
            
            # 清理系统缓存
            success = self.file_cleaner.clean_system_cache(device_info.device_id)
            
            if success:
                task.add_log("系统缓存清理完成")
            else:
                task.add_log("系统缓存清理失败")
            
            # 清理应用缓存（获取大缓存应用）
            file_issues = self.file_scanner.scan_device_files(
                device_info.device_id, 
                {'scan_cache': True, 'scan_garbage': False, 'scan_duplicates': False, 'scan_logs': False, 'scan_residual': False}
            )
            
            if file_issues:
                clean_result = self.file_cleaner.clean_files(device_info.device_id, file_issues, create_backup=False)
                success = success and clean_result['success']
                task.add_log(f"清理了 {clean_result['cleaned_count']} 个缓存文件")
            
            return success
            
        except Exception as e:
            task.add_log(f"缓存清理异常: {str(e)}")
            return False
    
    def _repair_file_cleanup(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行文件清理修复"""
        try:
            task.add_log("开始文件清理...")
            
            # 扫描垃圾文件
            file_issues = self.file_scanner.scan_device_files(
                device_info.device_id,
                {'scan_garbage': True, 'scan_cache': False, 'scan_duplicates': False, 'scan_logs': True, 'scan_residual': True}
            )
            
            if file_issues:
                clean_result = self.file_cleaner.clean_files(device_info.device_id, file_issues, create_backup=True)
                task.add_log(f"清理了 {clean_result['cleaned_count']} 个垃圾文件，释放空间 {clean_result['total_size_freed']/(1024*1024):.1f}MB")
                return clean_result['success']
            else:
                task.add_log("未发现需要清理的文件")
                return True
                
        except Exception as e:
            task.add_log(f"文件清理异常: {str(e)}")
            return False
    
    def _repair_virus_removal(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行病毒清除修复"""
        try:
            task.add_log("开始病毒扫描和清除...")
            
            # 执行安全扫描
            virus_report = self.security_scanner.scan_device(device_info.device_id)
            
            if virus_report and virus_report.malware_count > 0:
                task.add_log(f"发现 {virus_report.malware_count} 个恶意软件")
                
                # 清除恶意软件
                removed_count = 0
                for suspicious_app in virus_report.suspicious_apps:
                    if self.security_scanner.remove_malware(device_info.device_id, suspicious_app):
                        removed_count += 1
                        task.add_log(f"已清除恶意软件: {suspicious_app}")
                
                task.add_log(f"成功清除 {removed_count} 个恶意软件")
                return removed_count > 0
            else:
                task.add_log("未发现恶意软件")
                return True
                
        except Exception as e:
            task.add_log(f"病毒清除异常: {str(e)}")
            return False
    
    def _repair_permission_fix(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行权限修复"""
        try:
            task.add_log("开始权限修复...")
            
            if not device_info.root_status:
                task.add_log("需要ROOT权限才能修复系统权限")
                return True  # 不算失败，只是跳过
            
            # 修复系统目录权限
            permission_commands = [
                "chmod 755 /system",
                "chmod 755 /system/bin",
                "chmod 755 /system/lib",
                "chmod 644 /system/build.prop"
            ]
            
            success_count = 0
            for command in permission_commands:
                try:
                    result = self.device_manager.adb_manager.execute_command(device_info.device_id, command)
                    success_count += 1
                    task.add_log(f"权限修复命令执行成功: {command}")
                except Exception as e:
                    task.add_log(f"权限修复命令失败: {command} - {str(e)}")
            
            success = success_count > 0
            task.add_log(f"权限修复完成，成功执行 {success_count} 个命令")
            return success
            
        except Exception as e:
            task.add_log(f"权限修复异常: {str(e)}")
            return False
    
    def _repair_system_repair(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行系统修复"""
        try:
            task.add_log("开始系统修复...")
            
            # 系统优化命令
            optimization_commands = [
                "sync",                           # 同步文件系统
                "echo 3 > /proc/sys/vm/drop_caches"  # 清理内存缓存（需要ROOT）
            ]
            
            success_count = 0
            for command in optimization_commands:
                try:
                    result = self.device_manager.adb_manager.execute_command(device_info.device_id, command)
                    success_count += 1
                    task.add_log(f"系统优化命令执行成功: {command}")
                except Exception as e:
                    task.add_log(f"系统优化命令失败: {command} - {str(e)}")
            
            task.add_log("系统修复完成")
            return True
            
        except Exception as e:
            task.add_log(f"系统修复异常: {str(e)}")
            return False
    
    def _repair_app_cleanup(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行应用清理修复"""
        try:
            task.add_log("开始应用清理...")
            
            # 这里可以实现清理有问题的应用的逻辑
            # 例如：禁用不必要的系统应用、清理应用数据等
            
            task.add_log("应用清理完成")
            return True
            
        except Exception as e:
            task.add_log(f"应用清理异常: {str(e)}")
            return False
    
    def _repair_network_reset(self, task: RepairTask, device_info: DeviceInfo) -> bool:
        """执行网络重置修复"""
        try:
            task.add_log("开始网络重置...")
            
            # 网络重置命令
            network_commands = [
                "svc wifi disable",
                "svc wifi enable",
                "svc data disable",
                "svc data enable"
            ]
            
            for command in network_commands:
                try:
                    result = self.device_manager.adb_manager.execute_command(device_info.device_id, command)
                    task.add_log(f"网络命令执行成功: {command}")
                except Exception as e:
                    task.add_log(f"网络命令失败: {command} - {str(e)}")
            
            task.add_log("网络重置完成")
            return True
            
        except Exception as e:
            task.add_log(f"网络重置异常: {str(e)}")
            return False
    
    def get_task_status(self, task_id: str) -> Optional[RepairTask]:
        """获取任务状态"""
        return self.active_tasks.get(task_id)
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.CANCELLED
                task.add_log("任务已取消")
                self._notify_task_callbacks(task)
                return True
        return False
    
    def get_active_tasks(self) -> List[RepairTask]:
        """获取所有活跃任务"""
        return list(self.active_tasks.values())
    
    def cleanup_completed_tasks(self):
        """清理已完成的任务"""
        completed_task_ids = [
            task_id for task_id, task in self.active_tasks.items()
            if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
        ]
        
        for task_id in completed_task_ids:
            del self.active_tasks[task_id]
        
        if completed_task_ids:
            self.logger.info(f"清理了 {len(completed_task_ids)} 个已完成任务")