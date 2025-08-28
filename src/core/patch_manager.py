#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
补丁管理器 - 处理系统补丁的下载、安装、验证和回滚
"""

import os
import json
import time
import shutil
import hashlib
import requests
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from ..utils.logger import LoggerMixin


class PatchStatus(Enum):
    """补丁状态"""
    AVAILABLE = "AVAILABLE"      # 可用
    DOWNLOADING = "DOWNLOADING"  # 下载中
    DOWNLOADED = "DOWNLOADED"    # 已下载
    INSTALLING = "INSTALLING"    # 安装中
    INSTALLED = "INSTALLED"      # 已安装
    FAILED = "FAILED"           # 失败
    ROLLBACK = "ROLLBACK"       # 回滚


class PatchType(Enum):
    """补丁类型"""
    SECURITY = "SECURITY"        # 安全补丁
    SYSTEM = "SYSTEM"           # 系统补丁
    APPLICATION = "APPLICATION" # 应用补丁
    FIRMWARE = "FIRMWARE"       # 固件补丁


@dataclass
class PatchInfo:
    """补丁信息"""
    patch_id: str
    name: str
    version: str
    patch_type: PatchType
    description: str
    severity: str
    size: int
    download_url: str
    checksum: str
    dependencies: List[str] = field(default_factory=list)
    status: PatchStatus = PatchStatus.AVAILABLE
    install_date: Optional[datetime] = None
    backup_path: Optional[str] = None


@dataclass
class InstallResult:
    """安装结果"""
    success: bool
    patch_id: str
    message: str
    backup_created: bool = False
    rollback_available: bool = False


class PatchRepository(LoggerMixin):
    """补丁仓库管理"""
    
    def __init__(self, repo_path: str = "data/patch_repository"):
        self.repo_path = Path(repo_path)
        self.repo_path.mkdir(parents=True, exist_ok=True)
        
        self.cache_path = self.repo_path / "cache"
        self.cache_path.mkdir(exist_ok=True)
        
        self.metadata_file = self.repo_path / "patches.json"
        self.patches: Dict[str, PatchInfo] = {}
        
        self._load_patches()
    
    def _load_patches(self):
        """加载补丁元数据"""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for patch_data in data.get('patches', []):
                        patch = PatchInfo(**patch_data)
                        self.patches[patch.patch_id] = patch
                
                self.logger.info(f"加载补丁仓库: {len(self.patches)} 个补丁")
            else:
                self._create_initial_metadata()
        except Exception as e:
            self.logger.error(f"加载补丁仓库失败: {e}")
    
    def _create_initial_metadata(self):
        """创建初始补丁元数据"""
        initial_patches = [
            {
                "patch_id": "android_security_2024_01",
                "name": "Android安全补丁2024-01",
                "version": "2024.01.05",
                "patch_type": "SECURITY",
                "description": "修复多个安全漏洞",
                "severity": "HIGH",
                "size": 52428800,
                "download_url": "https://patches.android.com/security/2024-01.zip",
                "checksum": "sha256:abc123...",
                "dependencies": []
            }
        ]
        
        self._save_metadata(initial_patches)
    
    def _save_metadata(self, patches_data: List[Dict] = None):
        """保存补丁元数据"""
        try:
            if patches_data is None:
                patches_data = [
                    {
                        "patch_id": patch.patch_id,
                        "name": patch.name,
                        "version": patch.version,
                        "patch_type": patch.patch_type.value,
                        "description": patch.description,
                        "severity": patch.severity,
                        "size": patch.size,
                        "download_url": patch.download_url,
                        "checksum": patch.checksum,
                        "dependencies": patch.dependencies,
                        "status": patch.status.value,
                        "install_date": patch.install_date.isoformat() if patch.install_date else None,
                        "backup_path": patch.backup_path
                    }
                    for patch in self.patches.values()
                ]
            
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump({"patches": patches_data}, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"保存补丁元数据失败: {e}")
    
    def sync_remote_patches(self, remote_url: str) -> bool:
        """同步远程补丁信息"""
        try:
            response = requests.get(f"{remote_url}/patches.json", timeout=30)
            response.raise_for_status()
            
            remote_data = response.json()
            updated_count = 0
            
            for patch_data in remote_data.get('patches', []):
                patch_id = patch_data['patch_id']
                
                if patch_id not in self.patches:
                    patch = PatchInfo(**patch_data)
                    self.patches[patch_id] = patch
                    updated_count += 1
                    self.logger.info(f"发现新补丁: {patch.name}")
            
            if updated_count > 0:
                self._save_metadata()
                self.logger.info(f"同步完成，更新 {updated_count} 个补丁")
            
            return True
            
        except Exception as e:
            self.logger.error(f"同步远程补丁失败: {e}")
            return False
    
    def get_available_patches(self, patch_type: Optional[PatchType] = None) -> List[PatchInfo]:
        """获取可用补丁列表"""
        patches = list(self.patches.values())
        
        if patch_type:
            patches = [p for p in patches if p.patch_type == patch_type]
        
        # 按严重程度和发布时间排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        patches.sort(key=lambda p: (severity_order.get(p.severity, 4), p.patch_id))
        
        return patches
    
    def get_patch(self, patch_id: str) -> Optional[PatchInfo]:
        """获取指定补丁信息"""
        return self.patches.get(patch_id)


class PatchManager(LoggerMixin):
    """补丁管理器主类"""
    
    def __init__(self, device_manager, backup_manager):
        self.device_manager = device_manager
        self.backup_manager = backup_manager
        self.repository = PatchRepository()
        
        self.download_path = Path("data/downloads")
        self.download_path.mkdir(parents=True, exist_ok=True)
        
        self.install_history: List[Dict] = []
        self._load_install_history()
    
    def _load_install_history(self):
        """加载安装历史"""
        history_file = Path("data/patch_install_history.json")
        try:
            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as f:
                    self.install_history = json.load(f)
        except Exception as e:
            self.logger.error(f"加载安装历史失败: {e}")
    
    def _save_install_history(self):
        """保存安装历史"""
        history_file = Path("data/patch_install_history.json")
        try:
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(self.install_history, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            self.logger.error(f"保存安装历史失败: {e}")
    
    def download_patch(self, patch_id: str, progress_callback=None) -> bool:
        """下载补丁"""
        patch = self.repository.get_patch(patch_id)
        if not patch:
            self.logger.error(f"补丁不存在: {patch_id}")
            return False
        
        if patch.status == PatchStatus.DOWNLOADED:
            self.logger.info(f"补丁已下载: {patch_id}")
            return True
        
        try:
            patch.status = PatchStatus.DOWNLOADING
            download_file = self.download_path / f"{patch_id}.zip"
            
            self.logger.info(f"开始下载补丁: {patch.name}")
            
            response = requests.get(patch.download_url, stream=True, timeout=60)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(download_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress)
            
            # 验证校验和
            if self._verify_checksum(download_file, patch.checksum):
                patch.status = PatchStatus.DOWNLOADED
                self.repository._save_metadata()
                self.logger.info(f"补丁下载完成: {patch_id}")
                return True
            else:
                download_file.unlink()
                patch.status = PatchStatus.FAILED
                self.logger.error(f"补丁校验失败: {patch_id}")
                return False
                
        except Exception as e:
            patch.status = PatchStatus.FAILED
            self.logger.error(f"下载补丁失败 {patch_id}: {e}")
            return False
    
    def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """验证文件校验和"""
        try:
            if expected_checksum.startswith('sha256:'):
                expected = expected_checksum[7:]
                hasher = hashlib.sha256()
            elif expected_checksum.startswith('md5:'):
                expected = expected_checksum[4:]
                hasher = hashlib.md5()
            else:
                return True  # 跳过验证
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            return hasher.hexdigest().lower() == expected.lower()
            
        except Exception as e:
            self.logger.error(f"校验和验证失败: {e}")
            return False
    
    def install_patch(self, device_id: str, patch_id: str, create_backup: bool = True) -> InstallResult:
        """安装补丁"""
        patch = self.repository.get_patch(patch_id)
        if not patch:
            return InstallResult(False, patch_id, "补丁不存在")
        
        if patch.status != PatchStatus.DOWNLOADED:
            if not self.download_patch(patch_id):
                return InstallResult(False, patch_id, "补丁下载失败")
        
        try:
            patch.status = PatchStatus.INSTALLING
            self.logger.info(f"开始安装补丁: {patch.name}")
            
            # 创建备份
            backup_created = False
            if create_backup:
                backup_result = self.backup_manager.create_full_backup(device_id, f"patch_{patch_id}")
                backup_created = backup_result.get('success', False)
                if backup_created:
                    patch.backup_path = backup_result.get('backup_path')
            
            # 执行安装
            install_success = self._execute_install(device_id, patch)
            
            if install_success:
                patch.status = PatchStatus.INSTALLED
                patch.install_date = datetime.now()
                
                # 记录安装历史
                self.install_history.append({
                    'patch_id': patch_id,
                    'device_id': device_id,
                    'install_time': patch.install_date,
                    'backup_path': patch.backup_path,
                    'success': True
                })
                
                self.repository._save_metadata()
                self._save_install_history()
                
                self.logger.info(f"补丁安装成功: {patch_id}")
                return InstallResult(
                    True, patch_id, "安装成功", 
                    backup_created, True
                )
            else:
                patch.status = PatchStatus.FAILED
                return InstallResult(False, patch_id, "安装失败")
                
        except Exception as e:
            patch.status = PatchStatus.FAILED
            self.logger.error(f"安装补丁异常 {patch_id}: {e}")
            return InstallResult(False, patch_id, f"安装异常: {str(e)}")
    
    def _execute_install(self, device_id: str, patch: PatchInfo) -> bool:
        """执行补丁安装"""
        try:
            patch_file = self.download_path / f"{patch.patch_id}.zip"
            
            # 根据补丁类型执行不同的安装逻辑
            if patch.patch_type == PatchType.SECURITY:
                return self._install_security_patch(device_id, patch_file)
            elif patch.patch_type == PatchType.SYSTEM:
                return self._install_system_patch(device_id, patch_file)
            elif patch.patch_type == PatchType.APPLICATION:
                return self._install_app_patch(device_id, patch_file)
            else:
                self.logger.error(f"不支持的补丁类型: {patch.patch_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"执行安装失败: {e}")
            return False
    
    def _install_security_patch(self, device_id: str, patch_file: Path) -> bool:
        """安装安全补丁"""
        # 这里实现安全补丁的安装逻辑
        # 通常需要Root权限
        device_info = self.device_manager.get_device(device_id)
        if not device_info or not device_info.root_status:
            self.logger.error("安装安全补丁需要Root权限")
            return False
        
        # 模拟安装过程
        time.sleep(2)
        return True
    
    def _install_system_patch(self, device_id: str, patch_file: Path) -> bool:
        """安装系统补丁"""
        # 实现系统补丁安装
        time.sleep(3)
        return True
    
    def _install_app_patch(self, device_id: str, patch_file: Path) -> bool:
        """安装应用补丁"""
        # 实现应用补丁安装
        time.sleep(1)
        return True
    
    def rollback_patch(self, device_id: str, patch_id: str) -> bool:
        """回滚补丁"""
        try:
            patch = self.repository.get_patch(patch_id)
            if not patch or patch.status != PatchStatus.INSTALLED:
                self.logger.error(f"补丁未安装或不存在: {patch_id}")
                return False
            
            if not patch.backup_path:
                self.logger.error(f"没有备份文件，无法回滚: {patch_id}")
                return False
            
            self.logger.info(f"开始回滚补丁: {patch.name}")
            
            # 恢复备份
            restore_success = self._restore_backup(device_id, patch.backup_path)
            
            if restore_success:
                patch.status = PatchStatus.ROLLBACK
                patch.install_date = None
                
                # 更新历史记录
                self.install_history.append({
                    'patch_id': patch_id,
                    'device_id': device_id,
                    'rollback_time': datetime.now(),
                    'success': True,
                    'action': 'ROLLBACK'
                })
                
                self.repository._save_metadata()
                self._save_install_history()
                
                self.logger.info(f"补丁回滚成功: {patch_id}")
                return True
            else:
                self.logger.error(f"补丁回滚失败: {patch_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"回滚补丁异常 {patch_id}: {e}")
            return False
    
    def _restore_backup(self, device_id: str, backup_path: str) -> bool:
        """恢复备份"""
        try:
            return self.backup_manager.restore_backup(device_id, backup_path)
        except Exception as e:
            self.logger.error(f"恢复备份失败: {e}")
            return False
    
    def get_installed_patches(self, device_id: str) -> List[PatchInfo]:
        """获取已安装补丁列表"""
        installed_patches = []
        
        for patch in self.repository.patches.values():
            if patch.status == PatchStatus.INSTALLED:
                # 检查是否在此设备上安装
                for record in self.install_history:
                    if (record.get('patch_id') == patch.patch_id and 
                        record.get('device_id') == device_id and
                        record.get('success') and
                        record.get('action') != 'ROLLBACK'):
                        installed_patches.append(patch)
                        break
        
        return installed_patches
    
    def check_patch_dependencies(self, patch_id: str) -> Tuple[bool, List[str]]:
        """检查补丁依赖"""
        patch = self.repository.get_patch(patch_id)
        if not patch:
            return False, ["补丁不存在"]
        
        missing_deps = []
        
        for dep_id in patch.dependencies:
            dep_patch = self.repository.get_patch(dep_id)
            if not dep_patch or dep_patch.status != PatchStatus.INSTALLED:
                missing_deps.append(dep_id)
        
        return len(missing_deps) == 0, missing_deps
    
    def get_patch_statistics(self) -> Dict[str, Any]:
        """获取补丁统计信息"""
        total_patches = len(self.repository.patches)
        installed_count = sum(1 for p in self.repository.patches.values() 
                             if p.status == PatchStatus.INSTALLED)
        
        return {
            'total_patches': total_patches,
            'installed_patches': installed_count,
            'available_patches': total_patches - installed_count,
            'last_sync_time': datetime.now().isoformat(),
            'install_history_count': len(self.install_history)
        }