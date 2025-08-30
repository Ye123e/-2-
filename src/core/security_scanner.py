#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
病毒检测和安全扫描模块
负责检测和清除恶意软件、木马程序、可疑进程
"""

import os
import hashlib
import re
import json
import threading
from typing import List, Dict, Optional, Callable, Set
from datetime import datetime
from pathlib import Path

from ..models import (
    DeviceInfo, VirusReport, Issue, IssueCategory, 
    IssueSeverity
)
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

class VirusSignatureDatabase(LoggerMixin):
    """病毒特征库管理器"""
    
    def __init__(self, db_path: str = "data/virus_signatures"):
        """
        初始化病毒特征库
        
        Args:
            db_path: 特征库文件路径
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # 恶意应用签名数据库
        self.malware_hashes: Set[str] = set()
        
        # 可疑权限组合
        self.suspicious_permissions = [
            # 隐私窃取相关权限组合
            ['READ_CONTACTS', 'SEND_SMS', 'RECORD_AUDIO'],
            ['READ_SMS', 'WRITE_SMS', 'SEND_SMS'],
            ['ACCESS_FINE_LOCATION', 'SEND_SMS', 'INTERNET'],
            
            # 恶意行为相关权限组合
            ['DEVICE_ADMIN', 'INTERNET', 'SEND_SMS'],
            ['WRITE_EXTERNAL_STORAGE', 'INTERNET', 'WAKE_LOCK'],
            ['SYSTEM_ALERT_WINDOW', 'INTERNET', 'BOOT_COMPLETED']
        ]
        
        # 恶意包名模式
        self.malicious_package_patterns = [
            r'.*\.fake\..*',
            r'.*\.trojan\..*',
            r'.*\.malware\..*',
            r'.*\.virus\..*',
            r'com\.android\..*fake.*',
        ]
        
        # 网络黑名单（恶意服务器地址）
        self.network_blacklist = [
            'malicious-server.com',
            'evil-command.net',
            'trojan-control.org'
        ]
        
        self._load_signatures()
    
    def _load_signatures(self):
        """加载病毒特征库"""
        try:
            # 加载恶意应用哈希值
            hash_file = self.db_path / "malware_hashes.txt"
            if hash_file.exists():
                with open(hash_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        hash_value = line.strip()
                        if hash_value and len(hash_value) == 64:  # SHA256
                            self.malware_hashes.add(hash_value.lower())
            
            # 加载恶意包名列表
            package_file = self.db_path / "malicious_packages.json"
            if package_file.exists():
                with open(package_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'patterns' in data:
                        self.malicious_package_patterns.extend(data['patterns'])
            
            self.logger.info(f"加载病毒特征库: {len(self.malware_hashes)} 个哈希值")
            
        except Exception as e:
            self.logger.error(f"加载病毒特征库失败: {e}")
    
    def update_signatures(self) -> bool:
        """
        更新病毒特征库
        
        Returns:
            更新是否成功
        """
        try:
            # 这里可以从云端下载最新的病毒特征库
            # 为示例，我们添加一些已知的恶意应用哈希
            known_malware_hashes = [
                # 这些是示例哈希值，实际使用中应该从安全厂商获取
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
                "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1",
                "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2",
            ]
            
            self.malware_hashes.update(known_malware_hashes)
            
            # 保存更新的特征库
            hash_file = self.db_path / "malware_hashes.txt"
            with open(hash_file, 'w', encoding='utf-8') as f:
                for hash_value in sorted(self.malware_hashes):
                    f.write(f"{hash_value}\n")
            
            self.logger.info("病毒特征库更新完成")
            return True
            
        except Exception as e:
            self.logger.error(f"更新病毒特征库失败: {e}")
            return False
    
    def is_malicious_hash(self, file_hash: str) -> bool:
        """检查文件哈希是否为已知恶意软件"""
        return file_hash.lower() in self.malware_hashes
    
    def is_suspicious_permissions(self, permissions: List[str]) -> bool:
        """检查权限组合是否可疑"""
        permission_set = set(permissions)
        
        for suspicious_combo in self.suspicious_permissions:
            if set(suspicious_combo).issubset(permission_set):
                return True
        
        return False
    
    def is_malicious_package(self, package_name: str) -> bool:
        """检查包名是否匹配恶意模式"""
        for pattern in self.malicious_package_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        
        return False

class SecurityScanner(LoggerMixin):
    """安全扫描器"""
    
    def __init__(self, device_manager: DeviceManager, signature_db: VirusSignatureDatabase):
        """
        初始化安全扫描器
        
        Args:
            device_manager: 设备管理器
            signature_db: 病毒特征库
        """
        self.device_manager = device_manager
        self.signature_db = signature_db
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        self.quarantine_path = Path("data/quarantine")
        self.quarantine_path.mkdir(parents=True, exist_ok=True)
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调函数"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新扫描进度"""
        self.logger.info(f"安全扫描进度: {progress}% - {message}")
        
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def scan_device(self, device_id: str, scan_options: Dict[str, bool] = None) -> List[Issue]:
        """
        对设备进行安全扫描，返回问题列表
        
        Args:
            device_id: 设备ID
            scan_options: 扫描选项
            
        Returns:
            发现的安全问题列表
        """
        issues = []
        
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return issues
        
        if scan_options is None:
            scan_options = {
                'scan_apps': True,
                'scan_processes': True,
                'scan_permissions': True,
                'scan_network': True
            }
        
        try:
            self._update_progress(0, "开始安全扫描")
            
            # 扫描应用程序
            if scan_options.get('scan_apps', True):
                self._update_progress(20, "扫描应用程序")
                app_issues = self._scan_applications(device_id)
                issues.extend(app_issues)
            
            # 扫描进程
            if scan_options.get('scan_processes', True):
                self._update_progress(50, "扫描运行进程")
                process_issues = self._scan_processes(device_id)
                issues.extend(process_issues)
            
            # 扫描权限
            if scan_options.get('scan_permissions', True):
                self._update_progress(70, "检查应用权限")
                permission_issues = self._scan_permissions(device_id)
                issues.extend(permission_issues)
            
            # 扫描网络连接
            if scan_options.get('scan_network', True):
                self._update_progress(90, "检查网络连接")
                network_issues = self._scan_network_connections(device_id)
                issues.extend(network_issues)
            
            self._update_progress(100, f"安全扫描完成，发现 {len(issues)} 个安全问题")
            
            self.logger.info(f"安全扫描完成: {device_info.model}, 发现 {len(issues)} 个问题")
            return issues
            
        except Exception as e:
            error_msg = f"安全扫描异常: {str(e)}"
            self.logger.error(error_msg)
            issues.append(Issue(
                category="security",
                severity="medium",
                description=error_msg,
                auto_fixable=False
            ))
            return issues
    
    def _scan_applications(self, device_id: str) -> List[Issue]:
        """扫描应用程序"""
        issues = []
        
        try:
            # 获取应用列表
            packages_result = self.device_manager.adb_manager.execute_command(
                device_id, 'pm list packages -3 -f'  # 包括路径信息
            )
            
            if not packages_result:
                return issues
            
            packages = []
            for line in packages_result.strip().split('\n'):
                if line.startswith('package:'):
                    parts = line.replace('package:', '').split('=')
                    if len(parts) == 2:
                        apk_path = parts[0]
                        package_name = parts[1]
                        packages.append((package_name, apk_path))
            
            # 检查每个应用
            for package_name, apk_path in packages:
                # 检查包名是否可疑
                if self.signature_db.is_malicious_package(package_name):
                    issues.append(Issue(
                        category="security",
                        severity="critical",
                        description=f"发现可疑应用: {package_name}",
                        auto_fixable=True,
                        details={'package_name': package_name, 'apk_path': apk_path}
                    ))
                
                # 检查文件哈希（如果可能）
                file_hash = self._get_file_hash(device_id, apk_path)
                if file_hash and self.signature_db.is_malicious_hash(file_hash):
                    issues.append(Issue(
                        category="security",
                        severity="critical",
                        description=f"发现已知恶意软件: {package_name}",
                        auto_fixable=True,
                        details={'package_name': package_name, 'hash': file_hash}
                    ))
            
            # 检查系统应用的异常
            system_issues = self._check_system_apps(device_id)
            issues.extend(system_issues)
            
        except Exception as e:
            self.logger.error(f"应用扫描失败: {e}")
        
        return issues
    
    def _scan_processes(self, device_id: str) -> List[Issue]:
        """扫描运行进程"""
        issues = []
        
        try:
            # 获取运行进程列表
            processes_result = self.device_manager.adb_manager.execute_command(
                device_id, 'ps -A | head -20'  # 只检查前20个进程
            )
            
            if not processes_result:
                return issues
            
            suspicious_processes = [
                'cryptominer', 'adware', 'spyware', 'trojan',
                'backdoor', 'rootkit', 'keylogger'
            ]
            
            for line in processes_result.strip().split('\n')[1:]:  # 跳过标题行
                for suspicious in suspicious_processes:
                    if suspicious.lower() in line.lower():
                        issues.append(Issue(
                            category="security",
                            severity="high",
                            description=f"发现可疑进程: {suspicious}",
                            auto_fixable=True,
                            details={'process_info': line.strip()}
                        ))
                        break
            
            # 检查CPU占用率异常高的进程
            high_cpu_issues = self._check_high_cpu_processes(device_id)
            issues.extend(high_cpu_issues)
            
        except Exception as e:
            self.logger.error(f"进程扫描失败: {e}")
        
        return issues
    
    def _scan_permissions(self, device_id: str) -> List[Issue]:
        """扫描应用权限"""
        issues = []
        
        try:
            # 获取应用列表
            packages_result = self.device_manager.adb_manager.execute_command(
                device_id, 'pm list packages -3 | head -10'  # 只检查前10个应用
            )
            
            if not packages_result:
                return issues
            
            packages = [line.replace('package:', '').strip() 
                       for line in packages_result.strip().split('\n') 
                       if line.startswith('package:')]
            
            for package in packages:
                # 获取应用权限
                permissions_result = self.device_manager.adb_manager.execute_command(
                    device_id, f'dumpsys package {package} | grep permission'
                )
                
                if permissions_result:
                    permissions = []
                    for line in permissions_result.strip().split('\n'):
                        if 'android.permission.' in line:
                            # 提取权限名称
                            perm_match = re.search(r'android\.permission\.([A-Z_]+)', line)
                            if perm_match:
                                permissions.append(perm_match.group(1))
                    
                    # 检查权限组合是否可疑
                    if self.signature_db.is_suspicious_permissions(permissions):
                        issues.append(Issue(
                            category="security",
                            severity="high",
                            description=f"应用 {package} 具有可疑权限组合",
                            auto_fixable=True,
                            details={'package': package, 'permissions': permissions}
                        ))
            
        except Exception as e:
            self.logger.error(f"权限扫描失败: {e}")
        
        return issues
    
    def _scan_network_connections(self, device_id: str) -> List[Issue]:
        """扫描网络连接"""
        issues = []
        
        try:
            # 检查网络连接
            netstat_result = self.device_manager.adb_manager.execute_command(
                device_id, 'netstat -n | grep ESTABLISHED | head -10'
            )
            
            if netstat_result:
                for line in netstat_result.strip().split('\n'):
                    # 提取远程地址
                    parts = line.split()
                    if len(parts) >= 5:
                        remote_addr = parts[4]
                        if ':' in remote_addr:
                            ip_addr = remote_addr.split(':')[0]
                            
                            # 检查是否连接到黑名单服务器
                            for blacklisted in self.signature_db.network_blacklist:
                                if blacklisted in ip_addr:
                                    issues.append(Issue(
                                        category="security",
                                        severity="critical",
                                        description=f"检测到与恶意服务器的连接: {ip_addr}",
                                        auto_fixable=True,
                                        details={'remote_address': remote_addr}
                                    ))
                                    break
            
            # 检查异常的网络流量
            traffic_issues = self._check_network_traffic(device_id)
            issues.extend(traffic_issues)
            
        except Exception as e:
            self.logger.error(f"网络扫描失败: {e}")
        
        return issues
    
    def _get_file_hash(self, device_id: str, file_path: str) -> Optional[str]:
        """获取文件哈希值"""
        try:
            # 尝试获取文件大小和修改时间作为简单的"哈希"
            stat_result = self.device_manager.adb_manager.execute_command(
                device_id, f'stat {file_path} 2>/dev/null'
            )
            
            if stat_result and 'Size:' in stat_result:
                # 使用文件信息生成简单的标识符
                return hashlib.md5(stat_result.encode()).hexdigest()
            
            return None
            
        except Exception as e:
            self.logger.error(f"获取文件哈希失败: {e}")
            return None
    
    def _check_system_apps(self, device_id: str) -> List[Issue]:
        """检查系统应用的异常"""
        issues = []
        
        try:
            # 检查系统应用是否被替换
            critical_system_apps = [
                'com.android.systemui',
                'com.android.settings', 
                'com.android.phone',
                'com.android.launcher'
            ]
            
            for app in critical_system_apps:
                app_info = self.device_manager.adb_manager.execute_command(
                    device_id, f'pm path {app}'
                )
                
                if app_info and 'package:' in app_info:
                    # 检查应用是否在正常的系统目录
                    if '/system/' not in app_info and '/data/' in app_info:
                        issues.append(Issue(
                            category="security",
                            severity="high", 
                            description=f"系统应用安装位置异常: {app}",
                            auto_fixable=False,
                            details={'app': app, 'path': app_info}
                        ))
            
        except Exception as e:
            self.logger.error(f"检查系统应用失败: {e}")
        
        return issues
    
    def _check_high_cpu_processes(self, device_id: str) -> List[Issue]:
        """检查CPU占用率异常高的进程"""
        issues = []
        
        try:
            # 获取CPU使用情况
            top_result = self.device_manager.adb_manager.execute_command(
                device_id, 'top -n 1 | head -10'
            )
            
            if top_result:
                for line in top_result.strip().split('\n')[1:]:
                    if '%' in line:  # CPU使用率行
                        parts = line.split()
                        if len(parts) >= 9:
                            try:
                                cpu_percent = float(parts[8].replace('%', ''))
                                if cpu_percent > 50:  # CPU使用率超过50%
                                    process_name = parts[-1] if parts else 'Unknown'
                                    issues.append(Issue(
                                        category="security",
                                        severity="medium",
                                        description=f"进程 {process_name} CPU使用率过高: {cpu_percent}%",
                                        auto_fixable=True,
                                        details={'process': process_name, 'cpu_percent': cpu_percent}
                                    ))
                            except ValueError:
                                continue
            
        except Exception as e:
            self.logger.error(f"检查CPU使用情况失败: {e}")
        
        return issues
    
    def _check_network_traffic(self, device_id: str) -> List[Issue]:
        """检查异常的网络流量"""
        issues = []
        
        try:
            # 检查网络接口统计
            netstat_result = self.device_manager.adb_manager.execute_command(
                device_id, 'cat /proc/net/dev | grep -v "lo:"'
            )
            
            if netstat_result:
                lines = netstat_result.strip().split('\n')
                if len(lines) > 1:  # 跳过标题行
                    for line in lines[1:]:
                        if ':' in line:
                            parts = line.split()
                            if len(parts) >= 10:
                                try:
                                    rx_bytes = int(parts[1])
                                    tx_bytes = int(parts[9])
                                    
                                    # 如果数据传输量异常大（超过100MB）
                                    if rx_bytes > 100 * 1024 * 1024 or tx_bytes > 100 * 1024 * 1024:
                                        interface = parts[0].replace(':', '')
                                        issues.append(Issue(
                                            category="security",
                                            severity="medium",
                                            description=f"网络接口 {interface} 数据传输量异常",
                                            auto_fixable=False,
                                            details={
                                                'interface': interface,
                                                'rx_mb': rx_bytes / (1024 * 1024),
                                                'tx_mb': tx_bytes / (1024 * 1024)
                                            }
                                        ))
                                except ValueError:
                                    continue
            
        except Exception as e:
            self.logger.error(f"检查网络流量失败: {e}")
        
        return issues
    
    def scan_device(self, device_id: str, scan_options: Dict[str, bool] = None) -> VirusReport:
        """
        对设备进行安全扫描，返回问题列表
        
        Args:
            device_id: 设备ID
            scan_options: 扫描选项
            
        Returns:
            发现的安全问题列表
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return VirusReport(scan_time=datetime.now(), malware_count=0, threat_level="LOW")
        
        if scan_options is None:
            scan_options = {
                'scan_apps': True,
                'scan_processes': True,
                'scan_permissions': True,
                'scan_network': True,
                'scan_files': True
            }
        
        self.logger.info(f"开始安全扫描: {device_info.model} ({device_id})")
        self._update_progress(0, "初始化安全扫描...")
        
        # 创建扫描报告
        report = VirusReport(scan_time=datetime.now())
        
        scan_steps = []
        
        if scan_options.get('scan_apps', True):
            scan_steps.append(('应用安全扫描', self._scan_applications))
        if scan_options.get('scan_processes', True):
            scan_steps.append(('进程安全扫描', self._scan_processes))
        if scan_options.get('scan_network', True):
            scan_steps.append(('网络安全扫描', self._scan_network_connections))
        if scan_options.get('scan_files', True):
            scan_steps.append(('文件安全扫描', self._scan_system_files))
        
        total_steps = len(scan_steps)
        malware_count = 0
        
        for i, (step_name, step_func) in enumerate(scan_steps):
            progress = int((i / total_steps) * 90)
            self._update_progress(progress, f"正在执行: {step_name}")
            
            try:
                step_result = step_func(device_info)
                if step_result:
                    if 'malware_count' in step_result:
                        malware_count += step_result['malware_count']
                    if 'suspicious_apps' in step_result:
                        report.suspicious_apps.extend(step_result['suspicious_apps'])
                    if 'quarantine_files' in step_result:
                        report.quarantine_files.extend(step_result['quarantine_files'])
            
            except Exception as e:
                self.logger.error(f"安全扫描步骤失败 {step_name}: {e}")
        
        self._update_progress(95, "生成安全报告...")
        
        # 设置报告信息
        report.malware_count = malware_count
        report.threat_level = self._calculate_threat_level(report)
        
        self._update_progress(100, "安全扫描完成")
        
        self.logger.info(f"安全扫描完成，发现 {malware_count} 个恶意软件，威胁级别: {report.threat_level}")
        return report
    
    def _scan_applications(self, device_info: DeviceInfo) -> Dict[str, Any]:
        """扫描应用程序安全性"""
        result = {
            'malware_count': 0,
            'suspicious_apps': [],
            'quarantine_files': []
        }
        
        try:
            # 获取已安装应用列表
            apps_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "pm list packages -f"
            )
            
            if not apps_result:
                return result
            
            apps = apps_result.strip().split('\n')
            
            for app_line in apps:
                if '=' in app_line:
                    # 解析包信息：package:/path/to/app.apk=com.package.name
                    parts = app_line.split('=')
                    if len(parts) >= 2:
                        apk_path = parts[0].replace('package:', '')
                        package_name = parts[1]
                        
                        # 检查包名是否匹配恶意模式
                        if self.signature_db.is_malicious_package(package_name):
                            result['malware_count'] += 1
                            result['suspicious_apps'].append(package_name)
                            self.logger.warning(f"发现可疑应用包名: {package_name}")
                        
                        # 检查应用权限
                        permissions = self._get_app_permissions(device_info.device_id, package_name)
                        if self.signature_db.is_suspicious_permissions(permissions):
                            result['suspicious_apps'].append(package_name)
                            self.logger.warning(f"发现可疑权限组合: {package_name}")
                        
                        # 检查APK文件哈希（如果有ROOT权限）
                        if device_info.root_status:
                            apk_hash = self._calculate_apk_hash(device_info.device_id, apk_path)
                            if apk_hash and self.signature_db.is_malicious_hash(apk_hash):
                                result['malware_count'] += 1
                                result['suspicious_apps'].append(package_name)
                                self.logger.warning(f"发现恶意应用哈希: {package_name}")
        
        except Exception as e:
            self.logger.error(f"扫描应用程序失败: {e}")
        
        return result
    
    def _get_app_permissions(self, device_id: str, package_name: str) -> List[str]:
        """获取应用权限列表"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm list permissions {package_name}"
            )
            
            if result:
                permissions = []
                for line in result.split('\n'):
                    if 'permission:' in line:
                        permission = line.split('permission:')[1].strip()
                        permissions.append(permission)
                return permissions
        
        except Exception as e:
            self.logger.error(f"获取应用权限失败: {e}")
        
        return []
    
    def _calculate_apk_hash(self, device_id: str, apk_path: str) -> Optional[str]:
        """计算APK文件哈希值"""
        try:
            # 使用设备上的工具计算哈希
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"md5sum {apk_path} 2>/dev/null"
            )
            
            if result and ' ' in result:
                hash_value = result.split()[0]
                return hash_value
        
        except Exception as e:
            self.logger.error(f"计算APK哈希失败: {e}")
        
        return None
    
    def _scan_processes(self, device_info: DeviceInfo) -> Dict[str, Any]:
        """扫描运行进程安全性"""
        result = {
            'malware_count': 0,
            'suspicious_apps': [],
            'quarantine_files': []
        }
        
        try:
            # 获取运行进程列表
            ps_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "ps"
            )
            
            if ps_result:
                processes = ps_result.strip().split('\n')[1:]  # 跳过标题行
                
                suspicious_process_patterns = [
                    r'.*fake.*',
                    r'.*trojan.*',
                    r'.*malware.*',
                    r'.*keylogger.*',
                    r'.*backdoor.*'
                ]
                
                for process_line in processes:
                    parts = process_line.split()
                    if len(parts) >= 9:  # 进程信息通常有多个字段
                        process_name = parts[-1]  # 进程名通常在最后
                        
                        # 检查进程名是否匹配可疑模式
                        for pattern in suspicious_process_patterns:
                            if re.search(pattern, process_name, re.IGNORECASE):
                                result['malware_count'] += 1
                                result['suspicious_apps'].append(process_name)
                                self.logger.warning(f"发现可疑进程: {process_name}")
                                break
        
        except Exception as e:
            self.logger.error(f"扫描运行进程失败: {e}")
        
        return result
    
    def _scan_network_connections(self, device_info: DeviceInfo) -> Dict[str, Any]:
        """扫描网络连接安全性"""
        result = {
            'malware_count': 0,
            'suspicious_apps': [],
            'quarantine_files': []
        }
        
        try:
            # 检查网络连接
            netstat_result = self.device_manager.adb_manager.execute_command(
                device_info.device_id, "netstat -n 2>/dev/null | grep ESTABLISHED"
            )
            
            if netstat_result:
                connections = netstat_result.strip().split('\n')
                
                for connection in connections:
                    # 解析连接信息，查找可疑的外部连接
                    parts = connection.split()
                    if len(parts) >= 5:
                        foreign_address = parts[4]
                        
                        # 提取IP地址
                        if ':' in foreign_address:
                            ip_address = foreign_address.split(':')[0]
                            
                            # 检查是否连接到黑名单中的服务器
                            for blacklisted_domain in self.signature_db.network_blacklist:
                                try:
                                    import socket
                                    blacklisted_ip = socket.gethostbyname(blacklisted_domain)
                                    if ip_address == blacklisted_ip:
                                        result['malware_count'] += 1
                                        self.logger.warning(f"发现连接到恶意服务器: {ip_address}")
                                except:
                                    pass
        
        except Exception as e:
            self.logger.error(f"扫描网络连接失败: {e}")
        
        return result
    
    def _scan_system_files(self, device_info: DeviceInfo) -> Dict[str, Any]:
        """扫描系统文件安全性"""
        result = {
            'malware_count': 0,
            'suspicious_apps': [],
            'quarantine_files': []
        }
        
        if not device_info.root_status:
            self.logger.info("需要ROOT权限才能扫描系统文件")
            return result
        
        try:
            # 检查系统目录中的可疑文件
            suspicious_paths = [
                '/system/app',
                '/data/app',
                '/data/data'
            ]
            
            for path in suspicious_paths:
                files_result = self.device_manager.adb_manager.execute_command(
                    device_info.device_id, f"find {path} -name '*.apk' 2>/dev/null | head -20"
                )
                
                if files_result:
                    apk_files = files_result.strip().split('\n')
                    
                    for apk_file in apk_files:
                        if apk_file.strip():
                            # 检查文件名是否可疑
                            filename = os.path.basename(apk_file)
                            if any(keyword in filename.lower() for keyword in ['fake', 'trojan', 'malware']):
                                result['malware_count'] += 1
                                result['quarantine_files'].append(apk_file)
                                self.logger.warning(f"发现可疑系统文件: {apk_file}")
        
        except Exception as e:
            self.logger.error(f"扫描系统文件失败: {e}")
        
        return result
    
    def _calculate_threat_level(self, report: VirusReport) -> str:
        """计算威胁级别"""
        if report.malware_count >= 5:
            return "CRITICAL"
        elif report.malware_count >= 3:
            return "HIGH"
        elif report.malware_count >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def quarantine_file(self, device_id: str, file_path: str) -> bool:
        """
        隔离可疑文件
        
        Args:
            device_id: 设备ID
            file_path: 文件路径
            
        Returns:
            隔离是否成功
        """
        try:
            # 为隔离文件生成唯一名称
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(file_path)
            quarantine_filename = f"{timestamp}_{filename}"
            quarantine_file_path = self.quarantine_path / quarantine_filename
            
            # 从设备下载文件到隔离区
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"cat {file_path}"
            )
            
            if result:
                with open(quarantine_file_path, 'wb') as f:
                    f.write(result.encode('latin-1'))
                
                self.logger.info(f"文件已隔离: {file_path} -> {quarantine_file_path}")
                return True
        
        except Exception as e:
            self.logger.error(f"隔离文件失败: {e}")
        
        return False
    
    def remove_malware(self, device_id: str, package_name: str) -> bool:
        """
        移除恶意软件
        
        Args:
            device_id: 设备ID
            package_name: 包名
            
        Returns:
            移除是否成功
        """
        try:
            # 卸载恶意应用
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm uninstall {package_name}"
            )
            
            if result and 'Success' in result:
                self.logger.info(f"成功移除恶意软件: {package_name}")
                return True
            else:
                self.logger.error(f"移除恶意软件失败: {package_name}")
                return False
        
        except Exception as e:
            self.logger.error(f"移除恶意软件异常: {e}")
            return False

class RealTimeProtection(LoggerMixin):
    """实时防护"""
    
    def __init__(self, device_manager: DeviceManager, signature_db: VirusSignatureDatabase):
        self.device_manager = device_manager
        self.signature_db = signature_db
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self, device_id: str):
        """开始实时监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_device,
            args=(device_id,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info(f"开始实时防护监控: {device_id}")
    
    def stop_monitoring(self):
        """停止实时监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        self.logger.info("实时防护监控已停止")
    
    def _monitor_device(self, device_id: str):
        """设备监控线程"""
        import time
        
        while self.monitoring:
            try:
                # 检查新安装的应用
                self._check_new_apps(device_id)
                
                # 检查可疑进程
                self._check_suspicious_processes(device_id)
                
                time.sleep(30)  # 每30秒检查一次
                
            except Exception as e:
                self.logger.error(f"实时监控异常: {e}")
                time.sleep(60)  # 出错时等待更长时间
    
    def _check_new_apps(self, device_id: str):
        """检查新安装的应用"""
        # 这里可以实现检查新安装应用的逻辑
        pass
    
    def _check_suspicious_processes(self, device_id: str):
        """检查可疑进程"""
        # 这里可以实现检查可疑进程的逻辑
        pass
