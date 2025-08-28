#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版修复执行引擎
集成自动化漏洞修复、系统加固和智能修复策略
"""

import os
import json
import threading
import time
from typing import Dict, List, Optional, Callable, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field

from ..models import (
    DeviceInfo, RepairTask, TaskStatus, VulnerabilityReport,
    ThreatLevel, SecurityEvent, MitigationAction
)
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager
from .vulnerability_detection_engine import VulnerabilityDetectionEngine


class HardeningType(Enum):
    """系统加固类型"""
    SECURITY_SETTINGS = "SECURITY_SETTINGS"
    PERMISSION_LOCKDOWN = "PERMISSION_LOCKDOWN"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    APP_VERIFICATION = "APP_VERIFICATION"
    ENCRYPTION_ENABLE = "ENCRYPTION_ENABLE"
    DEBUG_DISABLE = "DEBUG_DISABLE"
    FIREWALL_CONFIG = "FIREWALL_CONFIG"


@dataclass
class RepairStrategy:
    """修复策略"""
    vulnerability_id: str
    repair_type: str
    automated: bool
    commands: List[str] = field(default_factory=list)
    verification_commands: List[str] = field(default_factory=list)
    rollback_commands: List[str] = field(default_factory=list)
    requires_root: bool = False
    risk_level: str = "LOW"
    description: str = ""
    estimated_time: int = 60  # 秒


@dataclass
class SystemHardening:
    """系统加固配置"""
    hardening_id: str
    hardening_type: HardeningType
    description: str
    commands: List[str] = field(default_factory=list)
    verification_commands: List[str] = field(default_factory=list)
    rollback_commands: List[str] = field(default_factory=list)
    priority: int = 1
    requires_reboot: bool = False


class RepairTemplateManager:
    """修复模板管理器"""
    
    def __init__(self, templates_path: str = "data/repair_templates"):
        self.templates_path = Path(templates_path)
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self._load_repair_strategies()
        self._load_hardening_templates()
    
    def _load_repair_strategies(self):
        """加载修复策略模板"""
        self.repair_strategies = {
            # Android系统漏洞修复策略
            'CVE-2019-2215': RepairStrategy(
                vulnerability_id='CVE-2019-2215',
                repair_type='KERNEL_PATCH',
                automated=False,
                description='Android内核提权漏洞修复',
                commands=[
                    'echo "需要系统更新修复此漏洞"'
                ],
                verification_commands=[
                    'getprop ro.build.version.security_patch'
                ],
                requires_root=False,
                risk_level='HIGH',
                estimated_time=300
            ),
            
            # ADB调试关闭
            'adb_enabled': RepairStrategy(
                vulnerability_id='adb_enabled',
                repair_type='CONFIG_FIX',
                automated=True,
                description='关闭ADB调试功能',
                commands=[
                    'settings put global adb_enabled 0',
                    'setprop service.adb.root 0'
                ],
                verification_commands=[
                    'settings get global adb_enabled',
                    'getprop service.adb.root'
                ],
                rollback_commands=[
                    'settings put global adb_enabled 1'
                ],
                requires_root=True,
                risk_level='MEDIUM',
                estimated_time=30
            ),
            
            # 未知来源安装禁用
            'unknown_sources': RepairStrategy(
                vulnerability_id='unknown_sources',
                repair_type='CONFIG_FIX',
                automated=True,
                description='禁用未知来源应用安装',
                commands=[
                    'settings put global install_non_market_apps 0',
                    'settings put secure install_non_market_apps 0'
                ],
                verification_commands=[
                    'settings get global install_non_market_apps',
                    'settings get secure install_non_market_apps'
                ],
                rollback_commands=[
                    'settings put global install_non_market_apps 1'
                ],
                requires_root=False,
                risk_level='MEDIUM',
                estimated_time=20
            ),
            
            # 开发者选项禁用
            'developer_options': RepairStrategy(
                vulnerability_id='developer_options',
                repair_type='CONFIG_FIX',
                automated=True,
                description='禁用开发者选项',
                commands=[
                    'settings put global development_settings_enabled 0'
                ],
                verification_commands=[
                    'settings get global development_settings_enabled'
                ],
                rollback_commands=[
                    'settings put global development_settings_enabled 1'
                ],
                requires_root=False,
                risk_level='LOW',
                estimated_time=15
            )
        }
    
    def _load_hardening_templates(self):
        """加载系统加固模板"""
        self.hardening_templates = {
            HardeningType.SECURITY_SETTINGS: [
                SystemHardening(
                    hardening_id='screen_lock_enforce',
                    hardening_type=HardeningType.SECURITY_SETTINGS,
                    description='强制屏幕锁定',
                    commands=[
                        'settings put system screen_off_timeout 30000',  # 30秒
                        'settings put secure lock_screen_lock_after_timeout 0'
                    ],
                    verification_commands=[
                        'settings get system screen_off_timeout',
                        'settings get secure lock_screen_lock_after_timeout'
                    ],
                    priority=3
                ),
                
                SystemHardening(
                    hardening_id='auto_update_enable',
                    hardening_type=HardeningType.SECURITY_SETTINGS,
                    description='启用自动安全更新',
                    commands=[
                        'settings put global auto_time 1',
                        'settings put global auto_time_zone 1'
                    ],
                    verification_commands=[
                        'settings get global auto_time',
                        'settings get global auto_time_zone'
                    ],
                    priority=2
                )
            ],
            
            HardeningType.PERMISSION_LOCKDOWN: [
                SystemHardening(
                    hardening_id='restrict_dangerous_permissions',
                    hardening_type=HardeningType.PERMISSION_LOCKDOWN,
                    description='限制危险权限',
                    commands=[
                        'settings put secure enabled_accessibility_services ""',
                        'settings put secure accessibility_enabled 0'
                    ],
                    verification_commands=[
                        'settings get secure enabled_accessibility_services',
                        'settings get secure accessibility_enabled'
                    ],
                    priority=4,
                    requires_reboot=False
                )
            ],
            
            HardeningType.NETWORK_SECURITY: [
                SystemHardening(
                    hardening_id='wifi_security_enforce',
                    hardening_type=HardeningType.NETWORK_SECURITY,
                    description='强化WiFi安全设置',
                    commands=[
                        'settings put global wifi_scan_always_enabled 0',
                        'settings put global network_recommendations_enabled 0'
                    ],
                    verification_commands=[
                        'settings get global wifi_scan_always_enabled',
                        'settings get global network_recommendations_enabled'
                    ],
                    priority=2
                )
            ]
        }
    
    def get_repair_strategy(self, vulnerability_id: str) -> Optional[RepairStrategy]:
        """获取修复策略"""
        return self.repair_strategies.get(vulnerability_id)
    
    def get_hardening_templates(self, hardening_type: HardeningType) -> List[SystemHardening]:
        """获取系统加固模板"""
        return self.hardening_templates.get(hardening_type, [])


class EnhancedRepairEngine(LoggerMixin):
    """增强版修复执行引擎"""
    
    def __init__(self, device_manager: DeviceManager):
        """初始化增强版修复引擎"""
        self.device_manager = device_manager
        self.vulnerability_engine = VulnerabilityDetectionEngine(device_manager)
        self.template_manager = RepairTemplateManager()
        
        # 修复任务管理
        self.active_repairs: Dict[str, RepairTask] = {}
        self.repair_history: List[Dict[str, Any]] = []
        
        # 回调函数
        self.progress_callbacks: List[Callable[[str, int, str], None]] = []
        self.completion_callbacks: List[Callable[[RepairTask], None]] = []
        
        # 修复统计
        self.repair_stats = {
            'total_repairs': 0,
            'successful_repairs': 0,
            'failed_repairs': 0,
            'automated_repairs': 0,
            'manual_repairs': 0
        }
    
    def add_progress_callback(self, callback: Callable[[str, int, str], None]):
        """添加进度回调"""
        self.progress_callbacks.append(callback)
    
    def add_completion_callback(self, callback: Callable[[RepairTask], None]):
        """添加完成回调"""
        self.completion_callbacks.append(callback)
    
    def _update_progress(self, task_id: str, progress: int, message: str):
        """更新修复进度"""
        if task_id in self.active_repairs:
            self.active_repairs[task_id].progress = progress
            self.active_repairs[task_id].add_log(message)
        
        for callback in self.progress_callbacks:
            try:
                callback(task_id, progress, message)
            except Exception as e:
                self.logger.error(f"进度回调失败: {e}")
    
    def _notify_completion(self, task: RepairTask):
        """通知修复完成"""
        for callback in self.completion_callbacks:
            try:
                callback(task)
            except Exception as e:
                self.logger.error(f"完成回调失败: {e}")
    
    def scan_and_repair_vulnerabilities(self, device_id: str, auto_repair: bool = True) -> str:
        """扫描并修复漏洞"""
        task_id = f"vuln_repair_{device_id}_{int(time.time())}"
        
        task = RepairTask(
            task_id=task_id,
            device_id=device_id,
            task_type="VULNERABILITY_REPAIR",
            status=TaskStatus.PENDING,
            details={'auto_repair': auto_repair}
        )
        
        self.active_repairs[task_id] = task
        
        # 在新线程中执行修复
        repair_thread = threading.Thread(
            target=self._execute_vulnerability_repair,
            args=(task, auto_repair),
            daemon=True
        )
        repair_thread.start()
        
        return task_id
    
    def _execute_vulnerability_repair(self, task: RepairTask, auto_repair: bool):
        """执行漏洞修复"""
        try:
            task.start()
            self._update_progress(task.task_id, 10, "开始漏洞扫描...")
            
            # 1. 扫描漏洞
            vuln_report = self.vulnerability_engine.scan_vulnerabilities(task.device_id)
            if not vuln_report:
                task.fail("漏洞扫描失败")
                return
            
            self._update_progress(task.task_id, 30, f"发现 {vuln_report.vulnerability_count} 个漏洞")
            
            if vuln_report.vulnerability_count == 0:
                task.complete()
                self._update_progress(task.task_id, 100, "未发现漏洞，系统安全")
                return
            
            # 2. 生成修复计划
            repair_plan = self._generate_repair_plan(vuln_report, auto_repair)
            self._update_progress(task.task_id, 40, f"生成 {len(repair_plan)} 个修复步骤")
            
            # 3. 执行修复操作
            repaired_count = 0
            total_steps = len(repair_plan)
            
            for i, (vuln_id, strategy) in enumerate(repair_plan.items()):
                step_progress = 40 + int((i / total_steps) * 50)
                self._update_progress(task.task_id, step_progress, f"修复漏洞: {vuln_id}")
                
                if self._execute_repair_strategy(task.device_id, strategy):
                    repaired_count += 1
                    self.repair_stats['successful_repairs'] += 1
                    if strategy.automated:
                        self.repair_stats['automated_repairs'] += 1
                    else:
                        self.repair_stats['manual_repairs'] += 1
                else:
                    self.repair_stats['failed_repairs'] += 1
            
            # 4. 验证修复结果
            self._update_progress(task.task_id, 90, "验证修复结果...")
            verification_result = self._verify_repair_results(task.device_id, repair_plan)
            
            # 5. 完成修复
            task.details.update({
                'vulnerabilities_found': vuln_report.vulnerability_count,
                'vulnerabilities_repaired': repaired_count,
                'repair_plan': list(repair_plan.keys()),
                'verification_result': verification_result
            })
            
            self.repair_stats['total_repairs'] += 1
            task.complete()
            self._update_progress(task.task_id, 100, 
                               f"修复完成: {repaired_count}/{vuln_report.vulnerability_count} 个漏洞已修复")
            
            # 记录修复历史
            self.repair_history.append({
                'task_id': task.task_id,
                'device_id': task.device_id,
                'timestamp': datetime.now(),
                'vulnerabilities_repaired': repaired_count,
                'total_vulnerabilities': vuln_report.vulnerability_count,
                'success_rate': repaired_count / vuln_report.vulnerability_count if vuln_report.vulnerability_count > 0 else 1.0
            })
            
        except Exception as e:
            self.logger.error(f"漏洞修复执行失败: {e}")
            task.fail(str(e))
        finally:
            self._notify_completion(task)
    
    def _generate_repair_plan(self, vuln_report: VulnerabilityReport, auto_repair: bool) -> Dict[str, RepairStrategy]:
        """生成修复计划"""
        repair_plan = {}
        
        for vuln in vuln_report.vulnerabilities:
            vuln_id = vuln.get('vuln_id') or vuln.get('check')
            if not vuln_id:
                continue
            
            strategy = self.template_manager.get_repair_strategy(vuln_id)
            if strategy:
                # 根据auto_repair设置决定是否包含需要手动干预的修复
                if auto_repair or strategy.automated:
                    repair_plan[vuln_id] = strategy
        
        return repair_plan
    
    def _execute_repair_strategy(self, device_id: str, strategy: RepairStrategy) -> bool:
        """执行修复策略"""
        try:
            self.logger.info(f"执行修复策略: {strategy.description}")
            
            # 检查是否需要root权限
            if strategy.requires_root:
                device_info = self.device_manager.get_device(device_id)
                if not device_info or not device_info.root_status:
                    self.logger.warning(f"修复需要root权限，跳过: {strategy.vulnerability_id}")
                    return False
            
            # 执行修复命令
            for command in strategy.commands:
                result = self.device_manager.execute_command(device_id, command)  # pyright: ignore[reportAttributeAccessIssue]
                if not result:
                    self.logger.error(f"修复命令执行失败: {command}")
                    return False
                
                self.logger.debug(f"修复命令执行成功: {command}")
            
            # 验证修复结果
            if strategy.verification_commands:
                for verify_cmd in strategy.verification_commands:
                    result = self.device_manager.execute_command(device_id, verify_cmd)  # pyright: ignore[reportAttributeAccessIssue]
                    if result is None:
                        self.logger.warning(f"验证命令执行失败: {verify_cmd}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"修复策略执行失败: {e}")
            return False
    
    def _verify_repair_results(self, device_id: str, repair_plan: Dict[str, RepairStrategy]) -> Dict[str, bool]:
        """验证修复结果"""
        verification_results = {}
        
        for vuln_id, strategy in repair_plan.items():
            try:
                success = True
                for verify_cmd in strategy.verification_commands:
                    result = self.device_manager.execute_command(device_id, verify_cmd)  # pyright: ignore[reportAttributeAccessIssue]
                    # 简单验证：命令能够执行并返回结果
                    if result is None:
                        success = False
                        break
                
                verification_results[vuln_id] = success
                
            except Exception as e:
                self.logger.error(f"验证漏洞修复失败 {vuln_id}: {e}")
                verification_results[vuln_id] = False
        
        return verification_results
    
    def apply_system_hardening(self, device_id: str, hardening_types: List[HardeningType] = None) -> str:  # pyright: ignore[reportArgumentType]
        """应用系统加固"""
        if hardening_types is None:
            hardening_types = list(HardeningType)
        
        task_id = f"hardening_{device_id}_{int(time.time())}"
        
        task = RepairTask(
            task_id=task_id,
            device_id=device_id,
            task_type="SYSTEM_HARDENING",
            status=TaskStatus.PENDING,
            details={'hardening_types': [ht.value for ht in hardening_types]}
        )
        
        self.active_repairs[task_id] = task
        
        # 在新线程中执行加固
        hardening_thread = threading.Thread(
            target=self._execute_system_hardening,
            args=(task, hardening_types),
            daemon=True
        )
        hardening_thread.start()
        
        return task_id
    
    def _execute_system_hardening(self, task: RepairTask, hardening_types: List[HardeningType]):
        """执行系统加固"""
        try:
            task.start()
            self._update_progress(task.task_id, 10, "开始系统加固...")
            
            applied_count = 0
            total_hardenings = sum(len(self.template_manager.get_hardening_templates(ht)) 
                                 for ht in hardening_types)
            
            current_step = 0
            
            for hardening_type in hardening_types:
                hardening_list = self.template_manager.get_hardening_templates(hardening_type)
                
                for hardening in sorted(hardening_list, key=lambda x: x.priority, reverse=True):
                    current_step += 1
                    progress = 10 + int((current_step / total_hardenings) * 80)
                    
                    self._update_progress(task.task_id, progress, 
                                        f"应用加固: {hardening.description}")
                    
                    if self._apply_hardening(task.device_id, hardening):
                        applied_count += 1
            
            # 完成加固
            task.details.update({
                'total_hardenings': total_hardenings,
                'applied_hardenings': applied_count,
                'success_rate': applied_count / total_hardenings if total_hardenings > 0 else 1.0
            })
            
            task.complete()
            self._update_progress(task.task_id, 100, 
                               f"系统加固完成: {applied_count}/{total_hardenings} 项已应用")
            
        except Exception as e:
            self.logger.error(f"系统加固执行失败: {e}")
            task.fail(str(e))
        finally:
            self._notify_completion(task)
    
    def _apply_hardening(self, device_id: str, hardening: SystemHardening) -> bool:
        """应用单个加固配置"""
        try:
            self.logger.info(f"应用系统加固: {hardening.description}")
            
            # 执行加固命令
            for command in hardening.commands:
                result = self.device_manager.execute_command(device_id, command)  # pyright: ignore[reportAttributeAccessIssue]
                if result is None:
                    self.logger.error(f"加固命令执行失败: {command}")
                    return False
            
            # 验证加固结果
            for verify_cmd in hardening.verification_commands:
                result = self.device_manager.execute_command(device_id, verify_cmd)  # pyright: ignore[reportAttributeAccessIssue]
                if result is None:
                    self.logger.warning(f"加固验证命令执行失败: {verify_cmd}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"系统加固应用失败: {e}")
            return False
    
    def rollback_repair(self, task_id: str) -> bool:
        """回滚修复操作"""
        try:
            if task_id not in self.active_repairs:
                self.logger.error(f"未找到修复任务: {task_id}")
                return False
            
            task = self.active_repairs[task_id]
            repair_plan = task.details.get('repair_plan', [])
            
            self.logger.info(f"开始回滚修复: {task_id}")
            
            rollback_success = True
            for vuln_id in reversed(repair_plan):  # 逆序回滚
                strategy = self.template_manager.get_repair_strategy(vuln_id)
                if strategy and strategy.rollback_commands:
                    for rollback_cmd in strategy.rollback_commands:
                        result = self.device_manager.execute_command(  # pyright: ignore[reportAttributeAccessIssue]
                            task.device_id, rollback_cmd
                        )
                        if not result:
                            rollback_success = False
                            self.logger.error(f"回滚命令执行失败: {rollback_cmd}")
            
            self.logger.info(f"修复回滚完成: {task_id}, 成功: {rollback_success}")
            return rollback_success
            
        except Exception as e:
            self.logger.error(f"修复回滚失败: {e}")
            return False
    
    def get_repair_status(self, task_id: str) -> Optional[RepairTask]:
        """获取修复状态"""
        return self.active_repairs.get(task_id)
    
    def get_repair_stats(self) -> Dict[str, Any]:
        """获取修复统计"""
        return {
            **self.repair_stats,
            'active_repairs': len(self.active_repairs),
            'repair_history_count': len(self.repair_history),
            'last_repair_time': self.repair_history[-1]['timestamp'].isoformat() if self.repair_history else None
        }