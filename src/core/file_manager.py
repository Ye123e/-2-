#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
错误文件检测和清理模块
负责识别并清理损坏文件、冗余文件、垃圾文件
"""

import os
import re
import hashlib
from typing import List, Dict, Optional, Callable, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from ..models import DeviceInfo, Issue, IssueCategory, IssueSeverity
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

class FileType(Enum):
    """文件类型枚举"""
    CORRUPTED = "CORRUPTED"           # 损坏文件
    DUPLICATE = "DUPLICATE"           # 重复文件
    GARBAGE = "GARBAGE"               # 垃圾文件
    RESIDUAL = "RESIDUAL"             # 残留文件
    INVALID_LINK = "INVALID_LINK"     # 无效链接
    LARGE_CACHE = "LARGE_CACHE"       # 大缓存文件
    OLD_LOG = "OLD_LOG"               # 旧日志文件

@dataclass
class FileIssue:
    """文件问题数据类"""
    file_path: str
    file_type: FileType
    size_bytes: int
    description: str
    safe_to_delete: bool = True
    backup_recommended: bool = False
    last_modified: Optional[datetime] = None
    
    @property
    def size_mb(self) -> float:
        """获取文件大小（MB）"""
        return self.size_bytes / (1024 * 1024)

class FileScanner(LoggerMixin):
    """文件扫描器"""
    
    def __init__(self, device_manager: DeviceManager):
        """
        初始化文件扫描器
        
        Args:
            device_manager: 设备管理器
        """
        self.device_manager = device_manager
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        
        # 垃圾文件模式
        self.garbage_patterns = [
            r'.*\.tmp$',              # 临时文件
            r'.*\.temp$',             # 临时文件
            r'.*\.cache$',            # 缓存文件
            r'.*\.log$',              # 日志文件（旧的）
            r'.*\.bak$',              # 备份文件
            r'.*\.old$',              # 旧文件
            r'.*~$',                  # 临时编辑文件
            r'.*\.thumbs$',           # 缩略图文件
            r'.*\.DS_Store$',         # macOS系统文件
            r'.*\.Trash.*',           # 回收站文件
        ]
        
        # 系统垃圾目录
        self.garbage_directories = [
            '/data/anr',              # ANR日志
            '/data/tombstones',       # 崩溃转储
            '/data/misc/bluetooth/logs',  # 蓝牙日志
            '/data/misc/wifi/logs',   # WiFi日志
            '/cache',                 # 系统缓存
            '/data/cache',            # 数据缓存
        ]
        
        # 应用缓存目录模式
        self.cache_directories = [
            '/data/data/*/cache',
            '/data/data/*/code_cache',
            '/storage/emulated/0/Android/data/*/cache',
            '/sdcard/Android/data/*/cache',
        ]
        
        # 大文件阈值（MB）
        self.large_file_threshold = 100
        
        # 旧文件阈值（天）
        self.old_file_threshold = 30
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调函数"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新扫描进度"""
        self.logger.info(f"文件扫描进度: {progress}% - {message}")
        
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def scan_device_files(self, device_id: str, scan_options: Dict[str, bool] = None) -> List[FileIssue]:
        """
        扫描设备文件问题
        
        Args:
            device_id: 设备ID
            scan_options: 扫描选项
            
        Returns:
            文件问题列表
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return []
        
        if scan_options is None:
            scan_options = {
                'scan_garbage': True,
                'scan_duplicates': True,
                'scan_cache': True,
                'scan_logs': True,
                'scan_residual': True
            }
        
        self.logger.info(f"开始文件扫描: {device_info.model} ({device_id})")
        self._update_progress(0, "初始化文件扫描...")
        
        file_issues = []
        scan_steps = []
        
        if scan_options.get('scan_garbage', True):
            scan_steps.append(('垃圾文件扫描', self._scan_garbage_files))
        if scan_options.get('scan_cache', True):
            scan_steps.append(('缓存文件扫描', self._scan_cache_files))
        if scan_options.get('scan_logs', True):
            scan_steps.append(('日志文件扫描', self._scan_log_files))
        if scan_options.get('scan_duplicates', True):
            scan_steps.append(('重复文件扫描', self._scan_duplicate_files))
        if scan_options.get('scan_residual', True):
            scan_steps.append(('残留文件扫描', self._scan_residual_files))
        
        total_steps = len(scan_steps)
        
        for i, (step_name, step_func) in enumerate(scan_steps):
            progress = int((i / total_steps) * 90)
            self._update_progress(progress, f"正在执行: {step_name}")
            
            try:
                step_issues = step_func(device_info)
                file_issues.extend(step_issues)
            except Exception as e:
                self.logger.error(f"文件扫描步骤失败 {step_name}: {e}")
        
        self._update_progress(95, "整理扫描结果...")
        
        # 按大小排序，大文件优先
        file_issues.sort(key=lambda x: x.size_bytes, reverse=True)
        
        self._update_progress(100, "文件扫描完成")
        
        total_size_mb = sum(issue.size_mb for issue in file_issues)
        self.logger.info(f"文件扫描完成，发现 {len(file_issues)} 个问题文件，总大小: {total_size_mb:.1f}MB")
        
        return file_issues
    
    def _scan_garbage_files(self, device_info: DeviceInfo) -> List[FileIssue]:
        """扫描垃圾文件"""
        issues = []
        
        try:
            # 扫描垃圾目录
            for garbage_dir in self.garbage_directories:
                files = self._get_directory_files(device_info.device_id, garbage_dir)
                
                for file_info in files:
                    if file_info['size'] > 0:  # 忽略空文件
                        issues.append(FileIssue(
                            file_path=file_info['path'],
                            file_type=FileType.GARBAGE,
                            size_bytes=file_info['size'],
                            description=f"垃圾文件: {os.path.basename(file_info['path'])}",
                            safe_to_delete=True
                        ))
            
            # 根据模式扫描垃圾文件
            scan_paths = ['/sdcard', '/storage/emulated/0']
            
            for scan_path in scan_paths:
                for pattern in self.garbage_patterns:
                    files = self._find_files_by_pattern(device_info.device_id, scan_path, pattern)
                    
                    for file_info in files:
                        issues.append(FileIssue(
                            file_path=file_info['path'],
                            file_type=FileType.GARBAGE,
                            size_bytes=file_info['size'],
                            description=f"临时文件: {os.path.basename(file_info['path'])}",
                            safe_to_delete=True
                        ))
        
        except Exception as e:
            self.logger.error(f"扫描垃圾文件失败: {e}")
        
        return issues
    
    def _scan_cache_files(self, device_info: DeviceInfo) -> List[FileIssue]:
        """扫描缓存文件"""
        issues = []
        
        try:
            # 扫描应用缓存目录
            for cache_pattern in self.cache_directories:
                # 使用通配符查找缓存目录
                cache_dirs = self._find_directories_by_pattern(device_info.device_id, cache_pattern)
                
                for cache_dir in cache_dirs:
                    # 计算缓存目录大小
                    dir_size = self._get_directory_size(device_info.device_id, cache_dir)
                    
                    if dir_size > self.large_file_threshold * 1024 * 1024:  # 大于阈值
                        app_name = self._extract_app_name_from_path(cache_dir)
                        
                        issues.append(FileIssue(
                            file_path=cache_dir,
                            file_type=FileType.LARGE_CACHE,
                            size_bytes=dir_size,
                            description=f"大缓存目录: {app_name}",
                            safe_to_delete=True
                        ))
        
        except Exception as e:
            self.logger.error(f"扫描缓存文件失败: {e}")
        
        return issues
    
    def _scan_log_files(self, device_info: DeviceInfo) -> List[FileIssue]:
        """扫描日志文件"""
        issues = []
        
        try:
            log_directories = [
                '/data/anr',
                '/data/tombstones',
                '/data/misc/bluetooth/logs',
                '/data/misc/wifi/logs'
            ]
            
            cutoff_date = datetime.now() - timedelta(days=self.old_file_threshold)
            
            for log_dir in log_directories:
                files = self._get_directory_files(device_info.device_id, log_dir)
                
                for file_info in files:
                    # 检查文件是否过旧
                    if file_info.get('modified_time'):
                        if file_info['modified_time'] < cutoff_date:
                            issues.append(FileIssue(
                                file_path=file_info['path'],
                                file_type=FileType.OLD_LOG,
                                size_bytes=file_info['size'],
                                description=f"旧日志文件: {os.path.basename(file_info['path'])}",
                                safe_to_delete=True,
                                last_modified=file_info['modified_time']
                            ))
        
        except Exception as e:
            self.logger.error(f"扫描日志文件失败: {e}")
        
        return issues
    
    def _scan_duplicate_files(self, device_info: DeviceInfo) -> List[FileIssue]:
        """扫描重复文件"""
        issues = []
        
        try:
            # 由于重复文件扫描比较复杂且耗时，这里做简化处理
            # 主要查找常见的重复文件模式
            
            common_paths = ['/sdcard/Download', '/sdcard/Pictures', '/sdcard/DCIM']
            file_hashes = {}
            
            for path in common_paths:
                files = self._get_directory_files(device_info.device_id, path)
                
                for file_info in files:
                    if file_info['size'] > 1024 * 1024:  # 只检查大于1MB的文件
                        # 简化的哈希计算（实际使用中应该计算完整哈希）
                        file_key = f"{file_info['size']}_{os.path.basename(file_info['path'])}"
                        
                        if file_key in file_hashes:
                            # 发现潜在重复文件
                            issues.append(FileIssue(
                                file_path=file_info['path'],
                                file_type=FileType.DUPLICATE,
                                size_bytes=file_info['size'],
                                description=f"可能的重复文件: {os.path.basename(file_info['path'])}",
                                safe_to_delete=False,  # 重复文件需要用户确认
                                backup_recommended=True
                            ))
                        else:
                            file_hashes[file_key] = file_info['path']
        
        except Exception as e:
            self.logger.error(f"扫描重复文件失败: {e}")
        
        return issues
    
    def _scan_residual_files(self, device_info: DeviceInfo) -> List[FileIssue]:
        """扫描残留文件"""
        issues = []
        
        try:
            # 获取已安装应用列表
            installed_apps = self._get_installed_packages(device_info.device_id)
            
            # 扫描数据目录中的残留文件
            data_dirs = self._get_directory_list(device_info.device_id, '/data/data')
            
            for data_dir in data_dirs:
                dir_name = os.path.basename(data_dir)
                
                # 检查目录对应的应用是否还存在
                if dir_name not in installed_apps:
                    dir_size = self._get_directory_size(device_info.device_id, data_dir)
                    
                    if dir_size > 0:
                        issues.append(FileIssue(
                            file_path=data_dir,
                            file_type=FileType.RESIDUAL,
                            size_bytes=dir_size,
                            description=f"已卸载应用的残留数据: {dir_name}",
                            safe_to_delete=True
                        ))
        
        except Exception as e:
            self.logger.error(f"扫描残留文件失败: {e}")
        
        return issues
    
    def _get_directory_files(self, device_id: str, directory: str) -> List[Dict]:
        """获取目录下的文件列表"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"find {directory} -type f -exec ls -la {{}} \\; 2>/dev/null | head -100"
            )
            
            files = []
            if result:
                for line in result.strip().split('\n'):
                    if line and not line.startswith('find:'):
                        file_info = self._parse_ls_output(line)
                        if file_info:
                            files.append(file_info)
            
            return files
        
        except Exception as e:
            self.logger.error(f"获取目录文件失败: {e}")
            return []
    
    def _parse_ls_output(self, ls_line: str) -> Optional[Dict]:
        """解析ls命令输出"""
        try:
            parts = ls_line.split()
            if len(parts) >= 9:
                size = int(parts[4]) if parts[4].isdigit() else 0
                file_path = ' '.join(parts[8:])
                
                return {
                    'path': file_path,
                    'size': size,
                    'modified_time': None  # 简化处理，不解析时间
                }
        except:
            pass
        
        return None
    
    def _find_files_by_pattern(self, device_id: str, base_path: str, pattern: str) -> List[Dict]:
        """根据模式查找文件"""
        try:
            # 将正则表达式模式转换为shell模式
            shell_pattern = pattern.replace('.*', '*').replace('$', '')
            
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"find {base_path} -name '{shell_pattern}' -type f 2>/dev/null | head -50"
            )
            
            files = []
            if result:
                for file_path in result.strip().split('\n'):
                    if file_path.strip():
                        # 获取文件大小
                        size_result = self.device_manager.adb_manager.execute_command(
                            device_id, f"wc -c < '{file_path}' 2>/dev/null"
                        )
                        
                        size = 0
                        if size_result and size_result.strip().isdigit():
                            size = int(size_result.strip())
                        
                        files.append({
                            'path': file_path.strip(),
                            'size': size
                        })
            
            return files
        
        except Exception as e:
            self.logger.error(f"按模式查找文件失败: {e}")
            return []
    
    def _find_directories_by_pattern(self, device_id: str, pattern: str) -> List[str]:
        """根据模式查找目录"""
        try:
            # 简化处理，直接使用find命令
            base_path = pattern.split('*')[0] if '*' in pattern else pattern
            
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"find {base_path} -type d -name cache 2>/dev/null | head -20"
            )
            
            directories = []
            if result:
                for dir_path in result.strip().split('\n'):
                    if dir_path.strip():
                        directories.append(dir_path.strip())
            
            return directories
        
        except Exception as e:
            self.logger.error(f"按模式查找目录失败: {e}")
            return []
    
    def _get_directory_size(self, device_id: str, directory: str) -> int:
        """获取目录大小"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"du -s {directory} 2>/dev/null"
            )
            
            if result:
                size_kb = int(result.strip().split()[0])
                return size_kb * 1024  # 转换为字节
        
        except Exception as e:
            self.logger.error(f"获取目录大小失败: {e}")
        
        return 0
    
    def _get_directory_list(self, device_id: str, base_path: str) -> List[str]:
        """获取目录列表"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"ls -1 {base_path} 2>/dev/null"
            )
            
            directories = []
            if result:
                for line in result.strip().split('\n'):
                    if line.strip():
                        directories.append(os.path.join(base_path, line.strip()))
            
            return directories
        
        except Exception as e:
            self.logger.error(f"获取目录列表失败: {e}")
            return []
    
    def _get_installed_packages(self, device_id: str) -> Set[str]:
        """获取已安装包列表"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, "pm list packages"
            )
            
            packages = set()
            if result:
                for line in result.strip().split('\n'):
                    if line.startswith('package:'):
                        package_name = line.replace('package:', '').strip()
                        packages.add(package_name)
            
            return packages
        
        except Exception as e:
            self.logger.error(f"获取已安装包列表失败: {e}")
            return set()
    
    def _extract_app_name_from_path(self, path: str) -> str:
        """从路径中提取应用名称"""
        parts = path.split('/')
        for part in parts:
            if part and '.' in part and not part.startswith('.'):
                return part
        return os.path.basename(path)

class FileCleaner(LoggerMixin):
    """文件清理器"""
    
    def __init__(self, device_manager: DeviceManager):
        """
        初始化文件清理器
        
        Args:
            device_manager: 设备管理器
        """
        self.device_manager = device_manager
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        self.backup_path = Path("backups")
        self.backup_path.mkdir(parents=True, exist_ok=True)
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调函数"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新清理进度"""
        self.logger.info(f"文件清理进度: {progress}% - {message}")
        
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def clean_files(self, device_id: str, file_issues: List[FileIssue], 
                   create_backup: bool = True) -> Dict[str, Any]:
        """
        清理文件
        
        Args:
            device_id: 设备ID
            file_issues: 要清理的文件问题列表
            create_backup: 是否创建备份
            
        Returns:
            清理结果字典
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            return {'success': False, 'error': '设备未找到'}
        
        self.logger.info(f"开始清理文件: {len(file_issues)} 个文件")
        self._update_progress(0, "初始化文件清理...")
        
        result = {
            'success': True,
            'cleaned_count': 0,
            'failed_count': 0,
            'total_size_freed': 0,
            'backup_created': False,
            'errors': []
        }
        
        # 创建备份（如果需要）
        if create_backup:
            backup_success = self._create_backup(device_id, file_issues)
            result['backup_created'] = backup_success
        
        total_files = len(file_issues)
        
        for i, file_issue in enumerate(file_issues):
            progress = int((i / total_files) * 90)
            self._update_progress(progress, f"清理文件: {os.path.basename(file_issue.file_path)}")
            
            try:
                if self._delete_file(device_id, file_issue):
                    result['cleaned_count'] += 1
                    result['total_size_freed'] += file_issue.size_bytes
                else:
                    result['failed_count'] += 1
                    result['errors'].append(f"删除失败: {file_issue.file_path}")
            
            except Exception as e:
                result['failed_count'] += 1
                result['errors'].append(f"删除异常: {file_issue.file_path} - {str(e)}")
                self.logger.error(f"删除文件异常: {e}")
        
        self._update_progress(100, "文件清理完成")
        
        total_size_mb = result['total_size_freed'] / (1024 * 1024)
        self.logger.info(f"文件清理完成，成功: {result['cleaned_count']}，失败: {result['failed_count']}，释放空间: {total_size_mb:.1f}MB")
        
        return result
    
    def _create_backup(self, device_id: str, file_issues: List[FileIssue]) -> bool:
        """创建备份"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = self.backup_path / f"backup_{device_id}_{timestamp}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # 只备份重要文件
            backup_files = [issue for issue in file_issues if issue.backup_recommended]
            
            if not backup_files:
                return True  # 没有需要备份的文件
            
            self.logger.info(f"创建备份: {len(backup_files)} 个文件")
            
            for file_issue in backup_files:
                try:
                    backup_file_path = backup_dir / os.path.basename(file_issue.file_path)
                    
                    # 从设备下载文件
                    result = self.device_manager.adb_manager.execute_command(
                        device_id, f"cat '{file_issue.file_path}'"
                    )
                    
                    if result:
                        with open(backup_file_path, 'wb') as f:
                            f.write(result.encode('latin-1'))
                
                except Exception as e:
                    self.logger.error(f"备份文件失败: {file_issue.file_path} - {e}")
            
            self.logger.info(f"备份创建完成: {backup_dir}")
            return True
        
        except Exception as e:
            self.logger.error(f"创建备份失败: {e}")
            return False
    
    def _delete_file(self, device_id: str, file_issue: FileIssue) -> bool:
        """删除单个文件或目录"""
        try:
            if file_issue.file_type == FileType.LARGE_CACHE:
                # 清理缓存目录
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"rm -rf '{file_issue.file_path}'/*"
                )
            else:
                # 删除文件
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"rm -f '{file_issue.file_path}'"
                )
            
            # 检查删除是否成功
            check_result = self.device_manager.adb_manager.execute_command(
                device_id, f"test -e '{file_issue.file_path}' && echo 'exists' || echo 'deleted'"
            )
            
            success = check_result and 'deleted' in check_result
            
            if success:
                self.logger.debug(f"文件删除成功: {file_issue.file_path}")
            else:
                self.logger.warning(f"文件删除失败: {file_issue.file_path}")
            
            return success
        
        except Exception as e:
            self.logger.error(f"删除文件异常: {file_issue.file_path} - {e}")
            return False
    
    def clean_app_cache(self, device_id: str, package_name: str) -> bool:
        """
        清理指定应用的缓存
        
        Args:
            device_id: 设备ID
            package_name: 应用包名
            
        Returns:
            清理是否成功
        """
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm clear {package_name}"
            )
            
            success = result and 'Success' in result
            
            if success:
                self.logger.info(f"应用缓存清理成功: {package_name}")
            else:
                self.logger.warning(f"应用缓存清理失败: {package_name}")
            
            return success
        
        except Exception as e:
            self.logger.error(f"清理应用缓存异常: {e}")
            return False
    
    def clean_system_cache(self, device_id: str) -> bool:
        """
        清理系统缓存
        
        Args:
            device_id: 设备ID
            
        Returns:
            清理是否成功
        """
        try:
            cache_commands = [
                "rm -rf /cache/*",                    # 系统缓存
                "rm -rf /data/dalvik-cache/*",        # Dalvik缓存
                "rm -rf /data/resource-cache/*",      # 资源缓存
            ]
            
            success_count = 0
            
            for command in cache_commands:
                try:
                    result = self.device_manager.adb_manager.execute_command(device_id, command)
                    success_count += 1
                except Exception as e:
                    self.logger.error(f"执行缓存清理命令失败: {command} - {e}")
            
            success = success_count > 0
            
            if success:
                self.logger.info("系统缓存清理完成")
            else:
                self.logger.warning("系统缓存清理失败")
            
            return success
        
        except Exception as e:
            self.logger.error(f"清理系统缓存异常: {e}")
            return False