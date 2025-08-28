#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资源扫描模块
负责扫描和检测Android系统中丢失的资源文件
包括系统库、框架组件、应用资源等
"""

import os
import hashlib
import json
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Callable

from ..models import ResourceReport, Issue, IssueCategory, IssueSeverity
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

class SystemResourceDatabase:
    """系统资源数据库"""
    
    def __init__(self, db_path: str):
        """
        初始化资源数据库
        
        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self.resources = {}
        self._load_database()
    
    def _load_database(self):
        """加载资源数据库"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.resources = json.load(f)
            except Exception as e:
                print(f"加载资源数据库失败: {e}")
                self._create_default_database()
        else:
            self._create_default_database()
    
    def _create_default_database(self):
        """创建默认资源数据库"""
        self.resources = {
            "system_libraries": {
                "/system/lib/libc.so": {
                    "description": "C标准库",
                    "critical": True,
                    "size_range": [800000, 2000000],
                    "architecture": ["arm", "arm64", "x86", "x86_64"]
                },
                "/system/lib/libm.so": {
                    "description": "数学库",
                    "critical": True,
                    "size_range": [100000, 500000],
                    "architecture": ["arm", "arm64", "x86", "x86_64"]
                },
                "/system/lib/libdl.so": {
                    "description": "动态链接库",
                    "critical": True,
                    "size_range": [10000, 50000],
                    "architecture": ["arm", "arm64", "x86", "x86_64"]
                },
                "/system/lib/liblog.so": {
                    "description": "日志库",
                    "critical": True,
                    "size_range": [20000, 100000],
                    "architecture": ["arm", "arm64", "x86", "x86_64"]
                },
                "/system/lib/libz.so": {
                    "description": "压缩库",
                    "critical": False,
                    "size_range": [50000, 200000],
                    "architecture": ["arm", "arm64", "x86", "x86_64"]
                }
            },
            "framework_components": {
                "/system/framework/framework.jar": {
                    "description": "Android核心框架",
                    "critical": True,
                    "size_range": [2000000, 10000000]
                },
                "/system/framework/android.policy.jar": {
                    "description": "Android策略框架",
                    "critical": True,
                    "size_range": [100000, 1000000]
                },
                "/system/framework/services.jar": {
                    "description": "系统服务框架",
                    "critical": True,
                    "size_range": [500000, 3000000]
                },
                "/system/framework/am.jar": {
                    "description": "活动管理器",
                    "critical": False,
                    "size_range": [50000, 300000]
                }
            },
            "system_apps": {
                "/system/app/Settings": {
                    "description": "系统设置应用",
                    "critical": True,
                    "is_directory": True
                },
                "/system/app/Calculator": {
                    "description": "计算器应用",
                    "critical": False,
                    "is_directory": True
                },
                "/system/priv-app/SystemUI": {
                    "description": "系统UI",
                    "critical": True,
                    "is_directory": True
                }
            },
            "system_binaries": {
                "/system/bin/sh": {
                    "description": "Shell解释器",
                    "critical": True,
                    "size_range": [100000, 500000]
                },
                "/system/bin/app_process": {
                    "description": "应用进程启动器",
                    "critical": True,
                    "size_range": [10000, 100000]
                },
                "/system/bin/servicemanager": {
                    "description": "服务管理器",
                    "critical": True,
                    "size_range": [10000, 100000]
                }
            },
            "config_files": {
                "/system/build.prop": {
                    "description": "系统构建属性",
                    "critical": True,
                    "is_text_file": True
                },
                "/system/etc/permissions/platform.xml": {
                    "description": "平台权限配置",
                    "critical": True,
                    "is_text_file": True
                }
            }
        }
        self.save_database()
    
    def save_database(self):
        """保存资源数据库"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(self.resources, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存资源数据库失败: {e}")
    
    def get_critical_resources(self) -> List[str]:
        """获取关键资源列表"""
        critical_resources = []
        
        for category, resources in self.resources.items():
            for path, info in resources.items():
                if info.get('critical', False):
                    critical_resources.append(path)
        
        return critical_resources
    
    def get_resource_info(self, resource_path: str) -> Optional[Dict[str, Any]]:
        """获取资源信息"""
        for category, resources in self.resources.items():
            if resource_path in resources:
                return resources[resource_path]
        return None

class ResourceScanner(LoggerMixin):
    """资源扫描器"""
    
    def __init__(self, device_manager: DeviceManager, config: Dict[str, Any]):
        """
        初始化资源扫描器
        
        Args:
            device_manager: 设备管理器
            config: 配置信息
        """
        self.device_manager = device_manager
        self.config = config
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        
        # 初始化资源数据库
        db_path = config.get('resource_db_path', 'data/system_resources/resources.json')
        self.resource_db = SystemResourceDatabase(db_path)
        
        # 扫描路径配置
        self.system_lib_paths = config.get('system_lib_paths', 
                                          '/system/lib,/system/lib64,/vendor/lib').split(',')
        self.framework_paths = config.get('framework_paths', '/system/framework').split(',')
        self.system_app_paths = config.get('system_app_paths', 
                                          '/system/app,/system/priv-app').split(',')
        
        # 检查选项
        self.verify_checksums = config.get('verify_checksums', True)
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调函数"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新扫描进度"""
        self.logger.info(f"资源扫描进度: {progress}% - {message}")
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def scan_resources(self, device_id: str) -> ResourceReport:
        """
        扫描设备资源完整性
        
        Args:
            device_id: 设备ID
            
        Returns:
            资源扫描报告
        """
        self.logger.info(f"开始扫描设备资源: {device_id}")
        self._update_progress(0, "初始化资源扫描...")
        
        report = ResourceReport(scan_time=datetime.now())
        
        try:
            # 扫描系统库文件
            self._update_progress(10, "扫描系统库文件...")
            library_issues = self._scan_system_libraries(device_id)
            report.corrupted_libraries.extend(library_issues)
            
            # 扫描框架组件
            self._update_progress(30, "扫描框架组件...")
            framework_issues = self._scan_framework_components(device_id)
            report.framework_issues.extend(framework_issues)
            
            # 扫描系统应用
            self._update_progress(50, "扫描系统应用...")
            missing_apps = self._scan_system_apps(device_id)
            report.missing_resources.extend(missing_apps)
            
            # 扫描系统二进制文件
            self._update_progress(70, "扫描系统二进制文件...")
            binary_issues = self._scan_system_binaries(device_id)
            report.missing_resources.extend(binary_issues)
            
            # 扫描配置文件
            self._update_progress(85, "扫描配置文件...")
            config_issues = self._scan_config_files(device_id)
            report.missing_resources.extend(config_issues)
            
            # 验证文件校验和
            if self.verify_checksums:
                self._update_progress(90, "验证文件完整性...")
                checksum_issues = self._verify_file_checksums(device_id)
                report.corrupted_libraries.extend(checksum_issues)
            
            # 检查修复可用性
            self._update_progress(95, "检查修复选项...")
            report.repair_available = self._check_repair_availability(report)
            
            self._update_progress(100, "资源扫描完成")
            
            # 统计结果
            total_issues = (len(report.missing_resources) + 
                          len(report.corrupted_libraries) + 
                          len(report.framework_issues))
            
            self.logger.info(f"资源扫描完成，发现 {total_issues} 个问题")
            
        except Exception as e:
            self.logger.error(f"资源扫描失败: {e}")
            report.missing_resources.append(f"扫描异常: {str(e)}")
        
        return report
    
    def _scan_system_libraries(self, device_id: str) -> List[str]:
        """扫描系统库文件"""
        corrupted_libs = []
        
        try:
            libraries = self.resource_db.resources.get('system_libraries', {})
            
            for lib_path, lib_info in libraries.items():
                # 检查文件是否存在
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -f {lib_path} && echo 'exists' || echo 'missing'"
                )
                
                if not result or 'missing' in result:
                    corrupted_libs.append(f"{lib_path} (文件缺失)")
                    continue
                
                # 检查文件大小是否合理
                size_result = self.device_manager.adb_manager.execute_command(
                    device_id, f"stat -c %s {lib_path} 2>/dev/null"
                )
                
                if size_result:
                    try:
                        file_size = int(size_result.strip())
                        size_range = lib_info.get('size_range', [0, float('inf')])
                        
                        if not (size_range[0] <= file_size <= size_range[1]):
                            corrupted_libs.append(f"{lib_path} (文件大小异常: {file_size} bytes)")
                    
                    except (ValueError, IndexError):
                        pass
                
                # 检查文件权限
                perm_result = self.device_manager.adb_manager.execute_command(
                    device_id, f"ls -l {lib_path} 2>/dev/null"
                )
                
                if perm_result and not perm_result.startswith('-r'):
                    corrupted_libs.append(f"{lib_path} (权限异常)")
        
        except Exception as e:
            self.logger.error(f"扫描系统库失败: {e}")
        
        return corrupted_libs
    
    def _scan_framework_components(self, device_id: str) -> List[str]:
        """扫描框架组件"""
        framework_issues = []
        
        try:
            frameworks = self.resource_db.resources.get('framework_components', {})
            
            for fw_path, fw_info in frameworks.items():
                # 检查框架文件是否存在
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -f {fw_path} && echo 'exists' || echo 'missing'"
                )
                
                if not result or 'missing' in result:
                    framework_issues.append(f"{fw_path} (框架文件缺失)")
                    continue
                
                # 检查JAR文件完整性
                if fw_path.endswith('.jar'):
                    jar_check = self.device_manager.adb_manager.execute_command(
                        device_id, f"unzip -t {fw_path} >/dev/null 2>&1 && echo 'valid' || echo 'invalid'"
                    )
                    
                    if jar_check and 'invalid' in jar_check:
                        framework_issues.append(f"{fw_path} (JAR文件损坏)")
        
        except Exception as e:
            self.logger.error(f"扫描框架组件失败: {e}")
        
        return framework_issues
    
    def _scan_system_apps(self, device_id: str) -> List[str]:
        """扫描系统应用"""
        missing_apps = []
        
        try:
            apps = self.resource_db.resources.get('system_apps', {})
            
            for app_path, app_info in apps.items():
                if app_info.get('is_directory', False):
                    # 检查目录是否存在
                    result = self.device_manager.adb_manager.execute_command(
                        device_id, f"test -d {app_path} && echo 'exists' || echo 'missing'"
                    )
                else:
                    # 检查文件是否存在
                    result = self.device_manager.adb_manager.execute_command(
                        device_id, f"test -f {app_path} && echo 'exists' || echo 'missing'"
                    )
                
                if not result or 'missing' in result:
                    missing_apps.append(f"{app_path} ({app_info.get('description', '系统应用')})")
        
        except Exception as e:
            self.logger.error(f"扫描系统应用失败: {e}")
        
        return missing_apps
    
    def _scan_system_binaries(self, device_id: str) -> List[str]:
        """扫描系统二进制文件"""
        missing_binaries = []
        
        try:
            binaries = self.resource_db.resources.get('system_binaries', {})
            
            for bin_path, bin_info in binaries.items():
                # 检查二进制文件是否存在并可执行
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -x {bin_path} && echo 'exists' || echo 'missing'"
                )
                
                if not result or 'missing' in result:
                    missing_binaries.append(f"{bin_path} ({bin_info.get('description', '系统二进制文件')})")
        
        except Exception as e:
            self.logger.error(f"扫描系统二进制文件失败: {e}")
        
        return missing_binaries
    
    def _scan_config_files(self, device_id: str) -> List[str]:
        """扫描配置文件"""
        missing_configs = []
        
        try:
            configs = self.resource_db.resources.get('config_files', {})
            
            for config_path, config_info in configs.items():
                # 检查配置文件是否存在
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"test -f {config_path} && echo 'exists' || echo 'missing'"
                )
                
                if not result or 'missing' in result:
                    missing_configs.append(f"{config_path} ({config_info.get('description', '配置文件')})")
                    continue
                
                # 如果是文本文件，检查内容是否为空
                if config_info.get('is_text_file', False):
                    size_result = self.device_manager.adb_manager.execute_command(
                        device_id, f"stat -c %s {config_path} 2>/dev/null"
                    )
                    
                    if size_result:
                        try:
                            file_size = int(size_result.strip())
                            if file_size == 0:
                                missing_configs.append(f"{config_path} (文件为空)")
                        except ValueError:
                            pass
        
        except Exception as e:
            self.logger.error(f"扫描配置文件失败: {e}")
        
        return missing_configs
    
    def _verify_file_checksums(self, device_id: str) -> List[str]:
        """验证文件校验和"""
        checksum_issues = []
        
        try:
            # 这里可以集成已知文件的校验和数据库
            # 为简化实现，暂时跳过具体的校验和验证
            self.logger.info("校验和验证功能需要完整的签名数据库支持")
        
        except Exception as e:
            self.logger.error(f"验证文件校验和失败: {e}")
        
        return checksum_issues
    
    def _check_repair_availability(self, report: ResourceReport) -> bool:
        """检查是否可以进行修复"""
        # 如果有丢失的关键资源，检查是否有可用的修复源
        critical_missing = []
        
        for missing_resource in report.missing_resources:
            # 提取文件路径
            resource_path = missing_resource.split(' (')[0]
            resource_info = self.resource_db.get_resource_info(resource_path)
            
            if resource_info and resource_info.get('critical', False):
                critical_missing.append(resource_path)
        
        # 如果有关键资源缺失，需要网络修复支持
        if critical_missing:
            return len(critical_missing) <= 5  # 如果关键缺失文件不超过5个，认为可修复
        
        return True

class ResourceDownloader(LoggerMixin):
    """资源下载器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化资源下载器
        
        Args:
            config: 配置信息
        """
        self.config = config
        self.server_url = config.get('resource_server_url', '')
        self.download_cache = config.get('download_cache', 'cache/downloads')
        
        # 创建下载缓存目录
        os.makedirs(self.download_cache, exist_ok=True)
    
    def download_resource(self, resource_path: str, device_info: Dict[str, str]) -> Optional[str]:
        """
        下载系统资源文件
        
        Args:
            resource_path: 资源文件路径
            device_info: 设备信息（型号、版本等）
            
        Returns:
            下载的文件本地路径，失败返回None
        """
        try:
            if not self.server_url:
                self.logger.warning("未配置资源服务器URL")
                return None
            
            # 构造下载请求
            download_url = f"{self.server_url}/download"
            params = {
                'resource': resource_path,
                'model': device_info.get('model', ''),
                'android_version': device_info.get('android_version', ''),
                'arch': device_info.get('cpu_arch', '')
            }
            
            self.logger.info(f"下载资源: {resource_path}")
            
            response = requests.get(download_url, params=params, timeout=30)
            response.raise_for_status()
            
            # 保存下载的文件
            filename = os.path.basename(resource_path) or 'resource_file'
            local_path = os.path.join(self.download_cache, filename)
            
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            self.logger.info(f"资源下载完成: {local_path}")
            return local_path
            
        except requests.RequestException as e:
            self.logger.error(f"下载资源失败: {e}")
            return None
        except Exception as e:
            self.logger.error(f"保存资源文件失败: {e}")
            return None
    
    def get_resource_checksum(self, resource_path: str, device_info: Dict[str, str]) -> Optional[str]:
        """
        获取资源文件的校验和
        
        Args:
            resource_path: 资源文件路径
            device_info: 设备信息
            
        Returns:
            文件的MD5校验和，失败返回None
        """
        try:
            if not self.server_url:
                return None
            
            checksum_url = f"{self.server_url}/checksum"
            params = {
                'resource': resource_path,
                'model': device_info.get('model', ''),
                'android_version': device_info.get('android_version', '')
            }
            
            response = requests.get(checksum_url, params=params, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            return result.get('md5')
            
        except Exception as e:
            self.logger.error(f"获取资源校验和失败: {e}")
            return None