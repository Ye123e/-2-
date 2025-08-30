#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统诊断引擎模块
负责执行各种系统问题的自动化诊断
"""

import re
import threading
from typing import List, Dict, Optional, Callable
from datetime import datetime
from pathlib import Path

from ..models import (
    DeviceInfo, DiagnosticReport, Issue, IssueCategory, 
    IssueSeverity, VirusReport, ResourceReport
)
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

class DiagnosticEngine(LoggerMixin):
    """系统诊断引擎"""
    
    def __init__(self, device_manager: DeviceManager):
        """
        初始化诊断引擎
        
        Args:
            device_manager: 设备管理器实例
        """
        self.device_manager = device_manager
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        self._current_progress = 0
        
        # 诊断规则配置
        self.storage_warning_threshold = 0.85  # 存储空间警告阈值（85%）
        self.storage_critical_threshold = 0.95  # 存储空间严重阈值（95%）
        
        # 系统关键文件列表
        self.critical_system_files = [
            '/system/build.prop',
            '/system/framework/framework.jar',
            '/system/framework/android.policy.jar',
            '/system/lib/libc.so',
            '/system/lib/libm.so',
            '/system/bin/sh',
            '/system/bin/app_process'
        ]
        
        # 系统关键目录
        self.critical_system_dirs = [
            '/system/app',
            '/system/framework',
            '/system/lib',
            '/system/bin',
            '/system/etc'
        ]
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """
        添加进度回调函数
        
        Args:
            callback: 回调函数，参数为(progress, message)
        """
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新诊断进度"""
        self._current_progress = progress
        self.logger.info(f"诊断进度: {progress}% - {message}")
        
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def diagnose_device(self, device_id: str, options: Dict[str, bool] = None) -> Optional[DiagnosticReport]:
        """
        对设备进行完整诊断
        
        Args:
            device_id: 设备ID
            options: 诊断选项字典
            
        Returns:
            诊断报告，失败返回None
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return None
        
        # 默认诊断选项
        if options is None:
            options = {
                'storage': True,
                'system_files': True,
                'resources': True,
                'virus': True,
                'error_files': True,
                'apps': True,
                'permissions': True,
                'network': True
            }
        
        self.logger.info(f"开始诊断设备: {device_info.model} ({device_id})")
        self._update_progress(0, "初始化诊断...")
        
        # 创建诊断报告
        report = DiagnosticReport(
            device_id=device_id,
            scan_time=datetime.now()
        )
        
        # 执行各项诊断
        diagnostic_steps = []
        
        if options.get('storage', True):
            diagnostic_steps.append(('存储空间检查', self._diagnose_storage))
        if options.get('system_files', True):
            diagnostic_steps.append(('系统文件检查', self._diagnose_system_files))
        if options.get('resources', True):
            diagnostic_steps.append(('资源完整性检查', self._diagnose_resources))
        if options.get('apps', True):
            diagnostic_steps.append(('应用程序检查', self._diagnose_applications))
        if options.get('permissions', True):
            diagnostic_steps.append(('权限配置检查', self._diagnose_permissions))
        if options.get('network', True):
            diagnostic_steps.append(('网络配置检查', self._diagnose_network))
        
        total_steps = len(diagnostic_steps)
        
        for i, (step_name, step_func) in enumerate(diagnostic_steps):
            progress = int((i / total_steps) * 90)  # 前90%用于诊断步骤
            self._update_progress(progress, f"正在执行: {step_name}")
            
            try:
                issues = step_func(device_info)
                if issues:
                    report.issues_found.extend(issues)
            except Exception as e:
                self.logger.error(f"诊断步骤失败 {step_name}: {e}")
                error_issue = Issue(
                    category=IssueCategory.SYSTEM_FILES,
                    severity=IssueSeverity.MEDIUM,
                    description=f"诊断步骤异常: {step_name} - {str(e)}",
                    auto_fixable=False
                )
                report.issues_found.append(error_issue)
        
        self._update_progress(95, "生成诊断报告...")
        
        # 计算系统健康评分
        report.system_health_score = self._calculate_health_score(report.issues_found)
        
        # 生成修复建议
        report.recommendations = self._generate_recommendations(report.issues_found)
        
        self._update_progress(100, "诊断完成")
        
        self.logger.info(f"诊断完成，发现 {len(report.issues_found)} 个问题，健康评分: {report.system_health_score}")
        return report
    
    def diagnose_storage(self, device_id: str) -> List[Issue]:
        """
        诊断存储空间问题
        
        Args:
            device_id: 设备ID
            
        Returns:
            发现的存储相关问题列表
        """
        device_info = self.device_manager.get_device(device_id)
        if device_info:
            return self._diagnose_storage(device_info)
        return []
    
    def diagnose_system_files(self, device_id: str) -> List[Issue]:
        """
        诊断系统文件完整性
        
        Args:
            device_id: 设备ID
            
        Returns:
            发现的系统文件相关问题列表
        """
        device_info = self.device_manager.get_device(device_id)
        if device_info:
            return self._diagnose_system_files(device_info)
        return []
    
    def diagnose_network(self, device_id: str) -> List[Issue]:
        """
        诺断网络配置问题
        
        Args:
            device_id: 设备ID
            
        Returns:
            发现的网络相关问题列表
        """
        issues = []
        
        try:
            # 检查网络连接状态
            connectivity_result = self.device_manager.adb_manager.execute_command(
                device_id, 'ping -c 3 8.8.8.8'
            )
            
            if not connectivity_result or '3 packets transmitted, 0 received' in connectivity_result:
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.HIGH,
                    description="无法连接到互联网",
                    auto_fixable=True
                ))
            elif 'packet loss' in connectivity_result and '100%' in connectivity_result:
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.MEDIUM,
                    description="网络连接不稳定",
                    auto_fixable=True
                ))
            
            # 检查WiFi状态
            wifi_result = self.device_manager.adb_manager.execute_command(
                device_id, 'dumpsys wifi | grep "Wi-Fi is"'
            )
            if wifi_result and 'disabled' in wifi_result.lower():
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.LOW,
                    description="WiFi已禁用",
                    auto_fixable=True
                ))
            
            # 检查DNS配置
            dns_result = self.device_manager.adb_manager.execute_command(
                device_id, 'nslookup google.com'
            )
            if not dns_result or 'server can\'t find' in dns_result.lower():
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.MEDIUM,
                    description="DNS解析异常",
                    auto_fixable=True
                ))
            
        except Exception as e:
            self.logger.error(f"网络诊断失败: {e}")
            issues.append(Issue(
                category=IssueCategory.NETWORK,
                severity=IssueSeverity.MEDIUM,
                description=f"网络论断异常: {str(e)}",
                auto_fixable=False
            ))
            
        return issues
    
    def diagnose_applications(self, device_id: str) -> List[Issue]:
        """
        论断应用程序问题
        
        Args:
            device_id: 设备ID
            
        Returns:
            发现的应用相关问题列表
        """
        issues = []
        
        try:
            # 获取安装的应用列表
            packages_result = self.device_manager.adb_manager.execute_command(
                device_id, 'pm list packages -3'  # 只列出第三方应用
            )
            
            if not packages_result:
                issues.append(Issue(
                    category=IssueCategory.APPLICATIONS,
                    severity=IssueSeverity.MEDIUM,
                    description="无法获取应用列表",
                    auto_fixable=False
                ))
                return issues
            
            packages = [line.replace('package:', '').strip() 
                       for line in packages_result.strip().split('\n') 
                       if line.startswith('package:')]
            
            # 检查崩溃的应用
            crashed_apps = self._check_crashed_apps(device_id, packages)
            if crashed_apps:
                issues.append(Issue(
                    category=IssueCategory.APPLICATIONS,
                    severity=IssueSeverity.MEDIUM,
                    description=f"发现 {len(crashed_apps)} 个应用程序崩溃",
                    auto_fixable=True,
                    details={'crashed_apps': crashed_apps}
                ))
            
            # 检查占用过多资源的应用
            resource_heavy_apps = self._check_resource_heavy_apps(device_id)
            if resource_heavy_apps:
                issues.append(Issue(
                    category=IssueCategory.APPLICATIONS,
                    severity=IssueSeverity.MEDIUM,
                    description=f"发现 {len(resource_heavy_apps)} 个应用占用过多资源",
                    auto_fixable=True,
                    details={'resource_heavy_apps': resource_heavy_apps}
                ))
                
        except Exception as e:
            self.logger.error(f"应用诊断失败: {e}")
            issues.append(Issue(
                category=IssueCategory.APPLICATIONS,
                severity=IssueSeverity.MEDIUM,
                description=f"应用诺断异常: {str(e)}",
                auto_fixable=False
            ))
            
        return issues
    
    def _diagnose_storage(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断存储空间问题"""
        issues = []
        
        if device_info.storage_total == 0:
            issues.append(Issue(
                category=IssueCategory.STORAGE,
                severity=IssueSeverity.MEDIUM,
                description="无法获取存储空间信息",
                auto_fixable=False
            ))
            return issues
        
        usage_percent = device_info.storage_usage_percent / 100
        
        if usage_percent >= self.storage_critical_threshold:
            issues.append(Issue(
                category=IssueCategory.STORAGE,
                severity=IssueSeverity.CRITICAL,
                description=f"存储空间严重不足 ({usage_percent:.1%}已使用)",
                auto_fixable=True,
                fix_method="清理缓存文件和临时数据",
                details={
                    'usage_percent': usage_percent,
                    'free_space_gb': device_info.storage_free / (1024**3),
                    'total_space_gb': device_info.storage_total / (1024**3)
                }
            ))
        elif usage_percent >= self.storage_warning_threshold:
            issues.append(Issue(
                category=IssueCategory.STORAGE,
                severity=IssueSeverity.HIGH,
                description=f"存储空间不足 ({usage_percent:.1%}已使用)",
                auto_fixable=True,
                fix_method="清理不必要的文件和应用",
                details={
                    'usage_percent': usage_percent,
                    'free_space_gb': device_info.storage_free / (1024**3),
                    'total_space_gb': device_info.storage_total / (1024**3)
                }
            ))
        
        # 检查缓存大小
        cache_issues = self._check_cache_size(device_info.device_id)
        issues.extend(cache_issues)
        
        return issues
    
    def _check_cache_size(self, device_id: str) -> List[Issue]:
        """检查应用缓存大小"""
        issues = []
        
        try:
            # 获取缓存目录大小
            result = self.device_manager.adb_manager.execute_command(
                device_id, "du -s /data/data/*/cache 2>/dev/null | sort -nr | head -10"
            )
            
            if result:
                total_cache_size = 0
                large_cache_apps = []
                
                for line in result.strip().split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            size_kb = int(parts[0])
                            cache_path = parts[1]
                            total_cache_size += size_kb
                            
                            # 如果单个应用缓存超过100MB，标记为问题
                            if size_kb > 100 * 1024:  # 100MB
                                app_name = cache_path.split('/')[-2] if '/' in cache_path else "未知应用"
                                large_cache_apps.append((app_name, size_kb))
                
                # 如果总缓存超过1GB，报告为问题
                if total_cache_size > 1024 * 1024:  # 1GB
                    issues.append(Issue(
                        category=IssueCategory.STORAGE,
                        severity=IssueSeverity.MEDIUM,
                        description=f"应用缓存过大 ({total_cache_size/(1024*1024):.1f}MB)",
                        auto_fixable=True,
                        fix_method="清理应用缓存",
                        details={
                            'total_cache_mb': total_cache_size / 1024,
                            'large_cache_apps': large_cache_apps
                        }
                    ))
        
        except Exception as e:
            self.logger.error(f"检查缓存大小失败: {e}")
        
        return issues
    
    def _diagnose_system_files(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断系统文件完整性"""
        issues = []
        
        if not device_info.root_status:
            issues.append(Issue(
                category=IssueCategory.SYSTEM_FILES,
                severity=IssueSeverity.LOW,
                description="需要ROOT权限才能完整检查系统文件",
                auto_fixable=False
            ))
            return issues
        
        missing_files = []
        corrupted_files = []
        
        # 检查关键系统文件是否存在
        for file_path in self.critical_system_files:
            result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, f"test -f {file_path} && echo 'exists' || echo 'missing'"
            )
            
            if result and 'missing' in result:
                missing_files.append(file_path)
        
        if missing_files:
            issues.append(Issue(
                category=IssueCategory.SYSTEM_FILES,
                severity=IssueSeverity.CRITICAL,
                description=f"发现 {len(missing_files)} 个关键系统文件缺失",
                auto_fixable=False,
                affected_files=missing_files,
                details={'missing_files': missing_files}
            ))
        
        # 检查系统目录权限
        permission_issues = self._check_system_permissions(device_info.device_id)
        issues.extend(permission_issues)
        
        return issues
    
    def _check_system_permissions(self, device_id: str) -> List[Issue]:
        """检查系统目录权限"""
        issues = []
        
        try:
            for dir_path in self.critical_system_dirs:
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"ls -ld {dir_path} 2>/dev/null"
                )
                
                if result:
                    # 解析权限信息
                    permission_line = result.strip().split('\n')[0]
                    if permission_line and not permission_line.startswith('d'):
                        issues.append(Issue(
                            category=IssueCategory.PERMISSIONS,
                            severity=IssueSeverity.HIGH,
                            description=f"系统目录权限异常: {dir_path}",
                            auto_fixable=True,
                            fix_method="修复目录权限",
                            affected_files=[dir_path]
                        ))
        
        except Exception as e:
            self.logger.error(f"检查系统权限失败: {e}")
        
        return issues
    
    def _diagnose_resources(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断系统资源完整性"""
        issues = []
        
        # 检查Framework JAR文件
        framework_issues = self._check_framework_integrity(device_info.device_id)
        issues.extend(framework_issues)
        
        # 检查系统库文件
        library_issues = self._check_system_libraries(device_info.device_id)
        issues.extend(library_issues)
        
        # 检查Dalvik缓存
        dalvik_issues = self._check_dalvik_cache(device_info.device_id)
        issues.extend(dalvik_issues)
        
        return issues
    
    def _check_framework_integrity(self, device_id: str) -> List[Issue]:
        """检查Framework完整性"""
        issues = []
        
        try:
            framework_files = [
                '/system/framework/framework.jar',
                '/system/framework/android.policy.jar',
                '/system/framework/services.jar'
            ]
            
            missing_frameworks = []
            
            for framework_file in framework_files:
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -f {framework_file} && echo 'exists' || echo 'missing'"
                )
                
                if result and 'missing' in result:
                    missing_frameworks.append(framework_file)
            
            if missing_frameworks:
                issues.append(Issue(
                    category=IssueCategory.RESOURCES,
                    severity=IssueSeverity.CRITICAL,
                    description=f"Framework组件缺失: {len(missing_frameworks)}个文件",
                    auto_fixable=False,
                    affected_files=missing_frameworks,
                    details={'missing_frameworks': missing_frameworks}
                ))
        
        except Exception as e:
            self.logger.error(f"检查Framework完整性失败: {e}")
        
        return issues
    
    def _check_system_libraries(self, device_id: str) -> List[Issue]:
        """检查系统库文件"""
        issues = []
        
        try:
            critical_libs = [
                '/system/lib/libc.so',
                '/system/lib/libm.so',
                '/system/lib/libdl.so',
                '/system/lib/liblog.so'
            ]
            
            missing_libs = []
            
            for lib_file in critical_libs:
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -f {lib_file} && echo 'exists' || echo 'missing'"
                )
                
                if result and 'missing' in result:
                    missing_libs.append(lib_file)
            
            if missing_libs:
                issues.append(Issue(
                    category=IssueCategory.RESOURCES,
                    severity=IssueSeverity.HIGH,
                    description=f"系统库文件缺失: {len(missing_libs)}个文件",
                    auto_fixable=True,
                    fix_method="重新安装系统库文件",
                    affected_files=missing_libs,
                    details={'missing_libraries': missing_libs}
                ))
        
        except Exception as e:
            self.logger.error(f"检查系统库文件失败: {e}")
        
        return issues
    
    def _check_dalvik_cache(self, device_id: str) -> List[Issue]:
        """检查Dalvik缓存"""
        issues = []
        
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, "ls -la /data/dalvik-cache/ 2>/dev/null | wc -l"
            )
            
            if result:
                cache_count = int(result.strip())
                if cache_count < 5:  # 如果缓存文件太少，可能有问题
                    issues.append(Issue(
                        category=IssueCategory.RESOURCES,
                        severity=IssueSeverity.MEDIUM,
                        description="Dalvik缓存文件过少，可能影响应用性能",
                        auto_fixable=True,
                        fix_method="重建Dalvik缓存",
                        details={'cache_file_count': cache_count}
                    ))
        
        except Exception as e:
            self.logger.error(f"检查Dalvik缓存失败: {e}")
        
        return issues
    
    def _diagnose_applications(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断应用程序问题"""
        issues = []
        
        try:
            # 获取已安装应用列表
            result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "pm list packages -f"
            )
            
            if result:
                apps = result.strip().split('\n')
                total_apps = len(apps)
                
                if total_apps > 200:  # 如果应用过多
                    issues.append(Issue(
                        category=IssueCategory.APPS,
                        severity=IssueSeverity.MEDIUM,
                        description=f"安装应用过多 ({total_apps}个)，可能影响性能",
                        auto_fixable=True,
                        fix_method="卸载不必要的应用",
                        details={'total_apps': total_apps}
                    ))
                
                # 检查是否有已知的问题应用
                problematic_apps = self._check_problematic_apps(apps)
                if problematic_apps:
                    issues.append(Issue(
                        category=IssueCategory.APPS,
                        severity=IssueSeverity.HIGH,
                        description=f"发现 {len(problematic_apps)} 个可能有问题的应用",
                        auto_fixable=True,
                        fix_method="卸载或更新问题应用",
                        details={'problematic_apps': problematic_apps}
                    ))
        
        except Exception as e:
            self.logger.error(f"诊断应用程序失败: {e}")
        
        return issues
    
    def _check_problematic_apps(self, apps: List[str]) -> List[str]:
        """检查已知的问题应用"""
        problematic_packages = [
            'com.android.packageinstaller',  # 有时会有权限问题
            'com.google.android.gms'  # 如果版本不匹配可能有问题
        ]
        
        found_problematic = []
        
        for app_line in apps:
            for problematic_pkg in problematic_packages:
                if problematic_pkg in app_line:
                    found_problematic.append(problematic_pkg)
        
        return found_problematic
    
    def _diagnose_permissions(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断权限配置问题"""
        issues = []
        
        try:
            # 检查关键目录的权限
            critical_paths = [
                '/data/data',
                '/system',
                '/data/app'
            ]
            
            for path in critical_paths:
                result = self.device_manager.adb_manager.execute_command(
                    device_info.device_id, f"ls -ld {path} 2>/dev/null"
                )
                
                if not result:
                    issues.append(Issue(
                        category=IssueCategory.PERMISSIONS,
                        severity=IssueSeverity.HIGH,
                        description=f"无法访问关键目录: {path}",
                        auto_fixable=False,
                        affected_files=[path]
                    ))
        
        except Exception as e:
            self.logger.error(f"诊断权限配置失败: {e}")
        
        return issues
    
    def _diagnose_network(self, device_info: DeviceInfo) -> List[Issue]:
        """诊断网络配置问题"""
        issues = []
        
        try:
            # 检查网络连接
            result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "ping -c 1 8.8.8.8 2>/dev/null && echo 'ok' || echo 'fail'"
            )
            
            if result and 'fail' in result:
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.MEDIUM,
                    description="网络连接异常，无法访问外部网络",
                    auto_fixable=True,
                    fix_method="检查WiFi或移动数据连接"
                ))
            
            # 检查DNS配置
            dns_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "getprop net.dns1"
            )
            
            if not dns_result or dns_result.strip() == "":
                issues.append(Issue(
                    category=IssueCategory.NETWORK,
                    severity=IssueSeverity.LOW,
                    description="DNS配置可能有问题",
                    auto_fixable=True,
                    fix_method="重置网络设置"
                ))
        
        except Exception as e:
            self.logger.error(f"诊断网络配置失败: {e}")
        
        return issues
    
    def _calculate_health_score(self, issues: List[Issue]) -> int:
        """计算系统健康评分"""
        base_score = 100
        
        for issue in issues:
            if issue.severity == IssueSeverity.CRITICAL:
                base_score -= 15
            elif issue.severity == IssueSeverity.HIGH:
                base_score -= 10
            elif issue.severity == IssueSeverity.MEDIUM:
                base_score -= 5
            elif issue.severity == IssueSeverity.LOW:
                base_score -= 2
        
        return max(0, base_score)
    
    def _generate_recommendations(self, issues: List[Issue]) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        # 按严重程度分类问题
        critical_issues = [i for i in issues if i.severity == IssueSeverity.CRITICAL]
        high_issues = [i for i in issues if i.severity == IssueSeverity.HIGH]
        
        if critical_issues:
            recommendations.append("立即处理关键问题，这些问题可能导致系统不稳定")
            for issue in critical_issues[:3]:  # 只显示前3个关键问题
                if issue.auto_fixable:
                    recommendations.append(f"- {issue.description} (可自动修复)")
                else:
                    recommendations.append(f"- {issue.description} (需要手动处理)")
        
        if high_issues:
            recommendations.append("处理高优先级问题，改善系统性能")
            for issue in high_issues[:3]:  # 只显示前3个高优先级问题
                if issue.auto_fixable:
                    recommendations.append(f"- {issue.description} (可自动修复)")
        
        # 通用建议
        storage_issues = [i for i in issues if i.category == IssueCategory.STORAGE]
        if storage_issues:
            recommendations.append("定期清理存储空间，保持足够的可用空间")
        
        app_issues = [i for i in issues if i.category == IssueCategory.APPS]
        if app_issues:
            recommendations.append("卸载不必要的应用，减少系统负担")
        
        if not recommendations:
            recommendations.append("系统状态良好，建议定期进行维护检查")
        
        return recommendations

class QuickDiagnostic(LoggerMixin):
    """快速诊断工具"""
    
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
    
    def quick_health_check(self, device_id: str) -> Dict[str, Any]:
        """
        快速健康检查
        
        Args:
            device_id: 设备ID
            
        Returns:
            健康检查结果字典
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            return {'error': '设备未连接'}
        
        result = {
            'device_id': device_id,
            'timestamp': datetime.now(),
            'storage_health': 'good',
            'system_health': 'good',
            'overall_score': 100,
            'warnings': []
        }
        
        # 存储健康检查
        if device_info.storage_total > 0:
            usage_percent = device_info.storage_usage_percent / 100
            
            if usage_percent >= 0.95:
                result['storage_health'] = 'critical'
                result['overall_score'] -= 30
                result['warnings'].append('存储空间严重不足')
            elif usage_percent >= 0.85:
                result['storage_health'] = 'warning'
                result['overall_score'] -= 15
                result['warnings'].append('存储空间不足')
        
        # 系统基本检查
        try:
            # 检查系统运行时间
            uptime_result = self.device_manager.adb_manager.execute_command(
                device_id, "cat /proc/uptime 2>/dev/null"
            )
            
            if uptime_result:
                uptime_seconds = float(uptime_result.strip().split()[0])
                uptime_hours = uptime_seconds / 3600
                
                if uptime_hours > 24 * 7:  # 运行超过一周
                    result['warnings'].append('建议重启设备')
                    result['overall_score'] -= 5
        
        except Exception as e:
            self.logger.error(f"快速检查失败: {e}")
            result['system_health'] = 'unknown'
        
        return result
    
    def _check_crashed_apps(self, device_id: str, packages: List[str]) -> List[str]:
        """检查崩溃的应用"""
        crashed_apps = []
        
        try:
            # 检查系统日志中的崩溃记录
            crash_result = self.device_manager.adb_manager.execute_command(
                device_id, 'logcat -d | grep "FATAL EXCEPTION" | tail -10'
            )
            
            if crash_result:
                for line in crash_result.strip().split('\n'):
                    for package in packages[:20]:  # 只检查前20个应用
                        if package in line and package not in crashed_apps:
                            crashed_apps.append(package)
                            break
        
        except Exception as e:
            self.logger.error(f"检查崩溃应用失败: {e}")
        
        return crashed_apps
    
    def _check_resource_heavy_apps(self, device_id: str) -> List[Dict[str, Any]]:
        """检查资源占用过多的应用"""
        heavy_apps = []
        
        try:
            # 获取内存使用情况
            mem_result = self.device_manager.adb_manager.execute_command(
                device_id, 'dumpsys meminfo | grep "Total PSS" | head -10'
            )
            
            if mem_result:
                for line in mem_result.strip().split('\n'):
                    if 'Total PSS' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            try:
                                pss_kb = int(parts[2].replace(',', ''))
                                if pss_kb > 100000:  # 超过100MB
                                    app_name = parts[0] if len(parts) > 0 else 'Unknown'
                                    heavy_apps.append({
                                        'app_name': app_name,
                                        'memory_mb': pss_kb / 1024
                                    })
                            except ValueError:
                                continue
        
        except Exception as e:
            self.logger.error(f"检查资源占用失败: {e}")
        
        return heavy_apps