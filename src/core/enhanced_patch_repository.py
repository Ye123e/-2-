#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强补丁仓库系统 - 提供本地缓存、远程同步、优先级管理
"""

import os
import json
import time
import sqlite3
import threading
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import requests
import hashlib

from ..utils.logger import LoggerMixin
from .patch_manager import PatchInfo, PatchStatus, PatchType


class SyncStatus(Enum):
    """同步状态"""
    IDLE = "IDLE"
    SYNCING = "SYNCING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class PatchPriority(Enum):
    """补丁优先级"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class RepositoryConfig:
    """仓库配置"""
    remote_url: str
    sync_interval: int = 3600  # 同步间隔(秒)
    cache_size_limit: int = 1024 * 1024 * 1024  # 缓存大小限制(1GB)
    auto_sync_enabled: bool = True
    retry_count: int = 3
    timeout: int = 30


@dataclass
class SyncReport:
    """同步报告"""
    sync_time: datetime
    status: SyncStatus
    patches_added: int = 0
    patches_updated: int = 0
    patches_removed: int = 0
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0


class EnhancedPatchRepository(LoggerMixin):
    """增强补丁仓库"""
    
    def __init__(self, repo_path: str = "data/patch_repository", config: RepositoryConfig = None):  # pyright: ignore[reportArgumentType]
        self.repo_path = Path(repo_path)
        self.repo_path.mkdir(parents=True, exist_ok=True)
        
        self.config = config or RepositoryConfig(
            remote_url="https://api.androidrepair.com/patches"
        )
        
        # 数据库连接
        self.db_path = self.repo_path / "patches.db"
        self._init_database()
        
        # 缓存目录
        self.cache_path = self.repo_path / "cache"
        self.cache_path.mkdir(exist_ok=True)
        
        # 同步状态
        self.sync_status = SyncStatus.IDLE
        self.last_sync_time: Optional[datetime] = None
        self.sync_thread: Optional[threading.Thread] = None
        self.auto_sync_running = False
        
        # 回调函数
        self.sync_callbacks: List[Callable[[SyncReport], None]] = []
        
        self._load_repository_metadata()
        
        if self.config.auto_sync_enabled:
            self._start_auto_sync()
    
    def _init_database(self):
        """初始化数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS patches (
                        patch_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        version TEXT NOT NULL,
                        patch_type TEXT NOT NULL,
                        description TEXT,
                        severity TEXT,
                        size INTEGER,
                        download_url TEXT,
                        checksum TEXT,
                        dependencies TEXT,
                        status TEXT,
                        priority INTEGER,
                        install_date TEXT,
                        backup_path TEXT,
                        created_time TEXT,
                        updated_time TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS sync_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sync_time TEXT NOT NULL,
                        status TEXT NOT NULL,
                        patches_added INTEGER DEFAULT 0,
                        patches_updated INTEGER DEFAULT 0,
                        patches_removed INTEGER DEFAULT 0,
                        duration REAL DEFAULT 0,
                        errors TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_patch_type ON patches(patch_type);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_patch_priority ON patches(priority);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_patch_status ON patches(status);
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化数据库失败: {e}")
    
    def _load_repository_metadata(self):
        """加载仓库元数据"""
        try:
            metadata_file = self.repo_path / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                    if 'last_sync_time' in metadata:
                        self.last_sync_time = datetime.fromisoformat(metadata['last_sync_time'])
        except Exception as e:
            self.logger.error(f"加载仓库元数据失败: {e}")
    
    def _save_repository_metadata(self):
        """保存仓库元数据"""
        try:
            metadata = {
                'last_sync_time': self.last_sync_time.isoformat() if self.last_sync_time else None,
                'config': {
                    'remote_url': self.config.remote_url,
                    'sync_interval': self.config.sync_interval,
                    'auto_sync_enabled': self.config.auto_sync_enabled
                }
            }
            
            metadata_file = self.repo_path / "metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"保存仓库元数据失败: {e}")
    
    def add_sync_callback(self, callback: Callable[[SyncReport], None]):
        """添加同步回调函数"""
        self.sync_callbacks.append(callback)
    
    def _notify_sync_complete(self, report: SyncReport):
        """通知同步完成"""
        for callback in self.sync_callbacks:
            try:
                callback(report)
            except Exception as e:
                self.logger.error(f"同步回调执行失败: {e}")
    
    def sync_with_remote(self, force: bool = False) -> SyncReport:
        """与远程仓库同步"""
        if self.sync_status == SyncStatus.SYNCING and not force:
            self.logger.warning("同步正在进行中")
            return SyncReport(datetime.now(), SyncStatus.FAILED, errors=["同步正在进行中"])
        
        self.sync_status = SyncStatus.SYNCING
        start_time = time.time()
        report = SyncReport(datetime.now(), SyncStatus.SYNCING)
        
        try:
            self.logger.info(f"开始与远程仓库同步: {self.config.remote_url}")
            
            # 获取远程补丁列表
            remote_patches = self._fetch_remote_patches()
            if not remote_patches:
                raise Exception("获取远程补丁列表失败")
            
            # 获取本地补丁列表
            local_patches = self._get_local_patches_dict()
            
            # 比较并更新
            for remote_patch in remote_patches:
                patch_id = remote_patch['patch_id']
                
                if patch_id not in local_patches:
                    # 新增补丁
                    self._add_patch_to_db(remote_patch)
                    report.patches_added += 1
                    self.logger.info(f"新增补丁: {patch_id}")
                    
                elif self._is_patch_updated(local_patches[patch_id], remote_patch):
                    # 更新补丁
                    self._update_patch_in_db(remote_patch)
                    report.patches_updated += 1
                    self.logger.info(f"更新补丁: {patch_id}")
            
            # 检查已删除的补丁
            remote_patch_ids = {p['patch_id'] for p in remote_patches}
            for local_patch_id in local_patches:
                if local_patch_id not in remote_patch_ids:
                    self._remove_patch_from_db(local_patch_id)
                    report.patches_removed += 1
                    self.logger.info(f"移除补丁: {local_patch_id}")
            
            self.last_sync_time = datetime.now()
            self.sync_status = SyncStatus.SUCCESS
            report.status = SyncStatus.SUCCESS
            
            self._save_repository_metadata()
            self.logger.info(f"同步完成: +{report.patches_added}, ~{report.patches_updated}, -{report.patches_removed}")
            
        except Exception as e:
            self.sync_status = SyncStatus.FAILED
            report.status = SyncStatus.FAILED
            report.errors.append(str(e))
            self.logger.error(f"同步失败: {e}")
        
        finally:
            report.duration = time.time() - start_time
            self._save_sync_history(report)
            self._notify_sync_complete(report)
        
        return report
    
    def _fetch_remote_patches(self) -> Optional[List[Dict]]:
        """获取远程补丁列表"""
        try:
            url = f"{self.config.remote_url}/patches.json"
            response = requests.get(
                url, 
                timeout=self.config.timeout,
                headers={'User-Agent': 'AndroidRepairTool/1.0'}
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get('patches', [])
            
        except Exception as e:
            self.logger.error(f"获取远程补丁列表失败: {e}")
            return None
    
    def _get_local_patches_dict(self) -> Dict[str, Dict]:
        """获取本地补丁字典"""
        patches = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM patches')
                
                for row in cursor:
                    patch_data = dict(row)
                    patches[patch_data['patch_id']] = patch_data
                    
        except Exception as e:
            self.logger.error(f"获取本地补丁失败: {e}")
        
        return patches
    
    def _is_patch_updated(self, local_patch: Dict, remote_patch: Dict) -> bool:
        """检查补丁是否已更新"""
        return (
            local_patch.get('version') != remote_patch.get('version') or
            local_patch.get('checksum') != remote_patch.get('checksum') or
            local_patch.get('description') != remote_patch.get('description')
        )
    
    def _add_patch_to_db(self, patch_data: Dict):
        """添加补丁到数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                priority = self._calculate_priority(patch_data)
                
                conn.execute('''
                    INSERT OR REPLACE INTO patches 
                    (patch_id, name, version, patch_type, description, severity,
                     size, download_url, checksum, dependencies, status, priority,
                     created_time, updated_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    patch_data['patch_id'],
                    patch_data['name'],
                    patch_data['version'],
                    patch_data['patch_type'],
                    patch_data.get('description', ''),
                    patch_data.get('severity', 'MEDIUM'),
                    patch_data.get('size', 0),
                    patch_data.get('download_url', ''),
                    patch_data.get('checksum', ''),
                    json.dumps(patch_data.get('dependencies', [])),
                    PatchStatus.AVAILABLE.value,
                    priority,
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                
        except Exception as e:
            self.logger.error(f"添加补丁到数据库失败: {e}")
    
    def _update_patch_in_db(self, patch_data: Dict):
        """更新数据库中的补丁"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                priority = self._calculate_priority(patch_data)
                
                conn.execute('''
                    UPDATE patches SET
                        name=?, version=?, patch_type=?, description=?, severity=?,
                        size=?, download_url=?, checksum=?, dependencies=?, priority=?,
                        updated_time=?
                    WHERE patch_id=?
                ''', (
                    patch_data['name'],
                    patch_data['version'],
                    patch_data['patch_type'],
                    patch_data.get('description', ''),
                    patch_data.get('severity', 'MEDIUM'),
                    patch_data.get('size', 0),
                    patch_data.get('download_url', ''),
                    patch_data.get('checksum', ''),
                    json.dumps(patch_data.get('dependencies', [])),
                    priority,
                    datetime.now().isoformat(),
                    patch_data['patch_id']
                ))
                
        except Exception as e:
            self.logger.error(f"更新补丁失败: {e}")
    
    def _remove_patch_from_db(self, patch_id: str):
        """从数据库中移除补丁"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM patches WHERE patch_id=?', (patch_id,))
                
        except Exception as e:
            self.logger.error(f"移除补丁失败: {e}")
    
    def _calculate_priority(self, patch_data: Dict) -> int:
        """计算补丁优先级"""
        severity = patch_data.get('severity', 'MEDIUM').upper()
        patch_type = patch_data.get('patch_type', 'SYSTEM').upper()
        
        # 基于严重程度的优先级
        severity_priority = {
            'CRITICAL': PatchPriority.CRITICAL.value,
            'HIGH': PatchPriority.HIGH.value,
            'MEDIUM': PatchPriority.MEDIUM.value,
            'LOW': PatchPriority.LOW.value
        }
        
        priority = severity_priority.get(severity, PatchPriority.MEDIUM.value)
        
        # 安全补丁提高优先级
        if patch_type == 'SECURITY':
            priority = max(1, priority - 1)
        
        return priority
    
    def _save_sync_history(self, report: SyncReport):
        """保存同步历史"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO sync_history 
                    (sync_time, status, patches_added, patches_updated, patches_removed, 
                     duration, errors)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    report.sync_time.isoformat(),
                    report.status.value,
                    report.patches_added,
                    report.patches_updated,
                    report.patches_removed,
                    report.duration,
                    json.dumps(report.errors)
                ))
                
        except Exception as e:
            self.logger.error(f"保存同步历史失败: {e}")
    
    def get_patches_by_priority(self, limit: int = 50) -> List[PatchInfo]:
        """按优先级获取补丁"""
        patches = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM patches 
                    ORDER BY priority ASC, severity DESC, patch_id DESC 
                    LIMIT ?
                ''', (limit,))
                
                for row in cursor:
                    patch = self._row_to_patch_info(row)
                    patches.append(patch)
                    
        except Exception as e:
            self.logger.error(f"获取优先级补丁失败: {e}")
        
        return patches
    
    def get_patches_by_type(self, patch_type: PatchType) -> List[PatchInfo]:
        """按类型获取补丁"""
        patches = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM patches 
                    WHERE patch_type = ?
                    ORDER BY priority ASC, patch_id DESC
                ''', (patch_type.value,))
                
                for row in cursor:
                    patch = self._row_to_patch_info(row)
                    patches.append(patch)
                    
        except Exception as e:
            self.logger.error(f"获取类型补丁失败: {e}")
        
        return patches
    
    def _row_to_patch_info(self, row: sqlite3.Row) -> PatchInfo:
        """数据库行转换为补丁信息对象"""
        dependencies = json.loads(row['dependencies'] or '[]')
        
        return PatchInfo(
            patch_id=row['patch_id'],
            name=row['name'],
            version=row['version'],
            patch_type=PatchType(row['patch_type']),
            description=row['description'],
            severity=row['severity'],
            size=row['size'],
            download_url=row['download_url'],
            checksum=row['checksum'],
            dependencies=dependencies,
            status=PatchStatus(row['status']),
            install_date=datetime.fromisoformat(row['install_date']) if row['install_date'] else None,
            backup_path=row['backup_path']
        )
    
    def _start_auto_sync(self):
        """启动自动同步"""
        if self.auto_sync_running:
            return
        
        self.auto_sync_running = True
        self.sync_thread = threading.Thread(target=self._auto_sync_worker, daemon=True)
        self.sync_thread.start()
        self.logger.info("自动同步已启动")
    
    def _auto_sync_worker(self):
        """自动同步工作线程"""
        while self.auto_sync_running:
            try:
                # 检查是否需要同步
                if self._should_sync():
                    self.sync_with_remote()
                
                # 等待下次检查
                time.sleep(60)  # 每分钟检查一次
                
            except Exception as e:
                self.logger.error(f"自动同步异常: {e}")
                time.sleep(300)  # 出错时等待5分钟
    
    def _should_sync(self) -> bool:
        """检查是否应该同步"""
        if not self.config.auto_sync_enabled:
            return False
        
        if self.sync_status == SyncStatus.SYNCING:
            return False
        
        if self.last_sync_time is None:
            return True
        
        time_since_last_sync = datetime.now() - self.last_sync_time
        return time_since_last_sync.total_seconds() >= self.config.sync_interval
    
    def stop_auto_sync(self):
        """停止自动同步"""
        self.auto_sync_running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        self.logger.info("自动同步已停止")
    
    def cleanup_cache(self):
        """清理缓存"""
        try:
            cache_size = self._get_cache_size()
            
            if cache_size > self.config.cache_size_limit:
                self.logger.info(f"缓存超限，开始清理: {cache_size / 1024 / 1024:.1f}MB")
                self._perform_cache_cleanup()
                
        except Exception as e:
            self.logger.error(f"清理缓存失败: {e}")
    
    def _get_cache_size(self) -> int:
        """获取缓存大小"""
        total_size = 0
        for file_path in self.cache_path.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size
    
    def _perform_cache_cleanup(self):
        """执行缓存清理"""
        # 删除最旧的文件直到满足大小限制
        files = []
        for file_path in self.cache_path.rglob('*'):
            if file_path.is_file():
                files.append((file_path.stat().st_mtime, file_path))
        
        files.sort()  # 按修改时间排序
        
        current_size = sum(f[1].stat().st_size for f in files)
        
        for mtime, file_path in files:
            if current_size <= self.config.cache_size_limit:
                break
            
            file_size = file_path.stat().st_size
            file_path.unlink()
            current_size -= file_size
            self.logger.debug(f"删除缓存文件: {file_path}")
    
    def get_repository_statistics(self) -> Dict[str, Any]:
        """获取仓库统计信息"""
        stats = {
            'total_patches': 0,
            'by_type': {},
            'by_status': {},
            'by_priority': {},
            'cache_size': 0,
            'last_sync_time': self.last_sync_time.isoformat() if self.last_sync_time else None,
            'sync_status': self.sync_status.value
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 总补丁数
                cursor = conn.execute('SELECT COUNT(*) FROM patches')
                stats['total_patches'] = cursor.fetchone()[0]
                
                # 按类型统计
                cursor = conn.execute('SELECT patch_type, COUNT(*) FROM patches GROUP BY patch_type')
                for row in cursor:
                    stats['by_type'][row[0]] = row[1]
                
                # 按状态统计
                cursor = conn.execute('SELECT status, COUNT(*) FROM patches GROUP BY status')
                for row in cursor:
                    stats['by_status'][row[0]] = row[1]
                
                # 按优先级统计
                cursor = conn.execute('SELECT priority, COUNT(*) FROM patches GROUP BY priority')
                for row in cursor:
                    priority_name = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}.get(row[0], 'UNKNOWN')
                    stats['by_priority'][priority_name] = row[1]
            
            # 缓存大小
            stats['cache_size'] = self._get_cache_size()
            
        except Exception as e:
            self.logger.error(f"获取仓库统计失败: {e}")
        
        return stats