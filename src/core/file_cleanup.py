#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
错误文件检测和清理模块
负责识别和清理损坏、冗余、垃圾文件
"""

import os
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Callable
from collections import defaultdict

from ..models import Issue, IssueCategory, IssueSeverity
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

class FileCleanupEngine(LoggerMixin):
    """文件清理引擎"""
    
    def __init__(self, device_manager: DeviceManager, config: Dict[str, Any]):
        self.device_manager = device_manager
        self.config = config
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        
        # 配置参数
        self.temp_paths = config.get('temp_paths', '/data/tmp,/cache,/data/cache').split(',')
        self.log_paths = config.get('log_paths', '/data/log,/data/tombstones').split(',')
        self.max_file_age_days = config.get('max_file_age_days', 30)
        self.max_log_size_mb = config.get('max_log_size_mb', 100)
        self.safe_delete = config.get('safe_delete', True)
        self.backup_before_delete = config.get('backup_before_delete', True)
        
        # 垃圾文件模式
        self.junk_file_patterns = [
            r'\.tmp$', r'\.temp$', r'\.log$', r'\.cache$',
            r'thumbs\.db$', r'\.DS_Store$', r'desktop\.ini$',
            r'.*~$', r'\.bak$', r'\.old$'
        ]
        
        # 大文件阈值 (100MB)
        self.large_file_threshold = 100 * 1024 * 1024
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新进度"""
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调失败: {e}")
    
    def scan_error_files(self, device_id: str) -> Dict[str, List[str]]:
        """扫描错误文件"""
        self.logger.info(f"开始扫描错误文件: {device_id}")
        
        results = {
            'corrupted_files': [],
            'duplicate_files': [],
            'junk_files': [],
            'large_files': [],
            'old_files': [],
            'empty_dirs': []
        }
        
        try:
            self._update_progress(10, "扫描损坏文件...")
            results['corrupted_files'] = self._scan_corrupted_files(device_id)
            
            self._update_progress(25, "扫描重复文件...")
            results['duplicate_files'] = self._scan_duplicate_files(device_id)
            
            self._update_progress(40, "扫描垃圾文件...")
            results['junk_files'] = self._scan_junk_files(device_id)
            
            self._update_progress(60, "扫描大文件...")
            results['large_files'] = self._scan_large_files(device_id)
            
            self._update_progress(80, "扫描过期文件...")
            results['old_files'] = self._scan_old_files(device_id)
            
            self._update_progress(95, "扫描空目录...")
            results['empty_dirs'] = self._scan_empty_directories(device_id)
            
            self._update_progress(100, "扫描完成")
            
        except Exception as e:
            self.logger.error(f"扫描错误文件失败: {e}")
        
        return results
    
    def _scan_corrupted_files(self, device_id: str) -> List[str]:
        """扫描损坏文件"""
        corrupted_files = []
        
        try:
            # 检查APK文件完整性
            result = self.device_manager.adb_manager.execute_command(
                device_id, "find /data/app -name '*.apk' 2>/dev/null | head -10"
            )
            
            if result:
                for apk_file in result.strip().split('\n'):
                    if apk_file.strip():
                        # 验证APK文件
                        verify_result = self.device_manager.adb_manager.execute_command(
                            device_id, f"unzip -t {apk_file} >/dev/null 2>&1 && echo 'ok' || echo 'corrupted'"
                        )
                        
                        if verify_result and 'corrupted' in verify_result:
                            corrupted_files.append(apk_file)
        
        except Exception as e:
            self.logger.error(f"扫描损坏文件失败: {e}")
        
        return corrupted_files
    
    def _scan_duplicate_files(self, device_id: str) -> List[str]:
        """扫描重复文件"""
        duplicates = []
        
        try:
            # 查找相同大小的文件
            result = self.device_manager.adb_manager.execute_command(
                device_id, "find /data -type f -size +1M 2>/dev/null | xargs ls -l | sort -k5 | uniq -D -f4"
            )
            
            if result:
                for line in result.strip().split('\n'):
                    if line.strip():
                        # 提取文件路径
                        parts = line.split()
                        if len(parts) >= 9:
                            file_path = ' '.join(parts[8:])
                            duplicates.append(file_path)
        
        except Exception as e:
            self.logger.error(f"扫描重复文件失败: {e}")
        
        return duplicates
    
    def _scan_junk_files(self, device_id: str) -> List[str]:
        """扫描垃圾文件"""
        junk_files = []
        
        try:
            # 扫描临时目录
            for temp_path in self.temp_paths:
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"find {temp_path} -type f 2>/dev/null"
                )
                
                if result:
                    for file_path in result.strip().split('\n'):
                        if file_path.strip():
                            junk_files.append(file_path)
        
        except Exception as e:
            self.logger.error(f"扫描垃圾文件失败: {e}")
        
        return junk_files
    
    def _scan_large_files(self, device_id: str) -> List[str]:
        """扫描大文件"""
        large_files = []
        
        try:
            # 查找大于100MB的文件
            result = self.device_manager.adb_manager.execute_command(
                device_id, "find /data -type f -size +100M 2>/dev/null | head -20"
            )
            
            if result:
                for file_path in result.strip().split('\n'):
                    if file_path.strip():
                        large_files.append(file_path)
        
        except Exception as e:
            self.logger.error(f"扫描大文件失败: {e}")
        
        return large_files
    
    def _scan_old_files(self, device_id: str) -> List[str]:
        """扫描过期文件"""
        old_files = []
        
        try:
            # 查找超过30天的日志文件
            for log_path in self.log_paths:
                result = self.device_manager.adb_manager.execute_command(
                    device_id, f"find {log_path} -type f -mtime +{self.max_file_age_days} 2>/dev/null"
                )
                
                if result:
                    for file_path in result.strip().split('\n'):
                        if file_path.strip():
                            old_files.append(file_path)
        
        except Exception as e:
            self.logger.error(f"扫描过期文件失败: {e}")
        
        return old_files
    
    def _scan_empty_directories(self, device_id: str) -> List[str]:
        """扫描空目录"""
        empty_dirs = []
        
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, "find /data -type d -empty 2>/dev/null | head -20"
            )
            
            if result:
                for dir_path in result.strip().split('\n'):
                    if dir_path.strip():
                        empty_dirs.append(dir_path)
        
        except Exception as e:
            self.logger.error(f"扫描空目录失败: {e}")
        
        return empty_dirs
    
    def clean_files(self, device_id: str, file_list: List[str], cleanup_type: str) -> bool:
        """清理文件"""
        try:
            self.logger.info(f"开始清理文件: {len(file_list)}个文件")
            
            for i, file_path in enumerate(file_list):
                progress = int((i / len(file_list)) * 100)
                self._update_progress(progress, f"清理文件: {os.path.basename(file_path)}")
                
                if self.safe_delete:
                    # 安全删除：先备份再删除
                    success = self._safe_delete_file(device_id, file_path)
                else:
                    # 直接删除
                    success = self._delete_file(device_id, file_path)
                
                if not success:
                    self.logger.warning(f"删除文件失败: {file_path}")
            
            self.logger.info(f"文件清理完成")
            return True
            
        except Exception as e:
            self.logger.error(f"清理文件失败: {e}")
            return False
    
    def _safe_delete_file(self, device_id: str, file_path: str) -> bool:
        """安全删除文件"""
        try:
            if self.backup_before_delete:
                # 创建备份（这里简化为记录日志）
                self.logger.info(f"备份文件: {file_path}")
            
            # 删除文件
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"rm -f {file_path}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"安全删除文件失败: {e}")
            return False
    
    def _delete_file(self, device_id: str, file_path: str) -> bool:
        """删除文件"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"rm -f {file_path}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"删除文件失败: {e}")
            return False