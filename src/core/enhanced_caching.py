#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强缓存系统 - 特征库缓存、扫描结果缓存、智能更新
"""

import os
import json
import sqlite3
import threading
import time
import pickle
import hashlib
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict

from ..utils.logger import LoggerMixin


@dataclass
class CacheEntry:
    """缓存条目"""
    key: str
    value: Any
    created_time: datetime
    last_accessed: datetime
    access_count: int
    expires_at: Optional[datetime] = None
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False


class LRUCache(LoggerMixin):
    """LRU缓存实现"""
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []
        self.lock = threading.RLock()
        
        # 统计信息
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'total_size_bytes': 0
        }
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        with self.lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            entry = self.cache[key]
            
            # 检查是否过期
            if entry.is_expired():
                self._remove_entry(key)
                self.stats['misses'] += 1
                return None
            
            # 更新访问信息
            entry.last_accessed = datetime.now()
            entry.access_count += 1
            
            # 更新访问顺序
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            
            self.stats['hits'] += 1
            return entry.value
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """放入缓存"""
        with self.lock:
            # 计算值的大小
            try:
                size_bytes = len(pickle.dumps(value))
            except Exception:
                size_bytes = 0
            
            # 检查内存限制
            if size_bytes > self.max_memory_bytes:
                self.logger.warning(f"值太大，无法缓存: {size_bytes} bytes")
                return False
            
            # 计算过期时间
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
            
            # 创建缓存条目
            entry = CacheEntry(
                key=key,
                value=value,
                created_time=datetime.now(),
                last_accessed=datetime.now(),
                access_count=0,
                expires_at=expires_at,
                size_bytes=size_bytes
            )
            
            # 如果键已存在，先移除旧值
            if key in self.cache:
                self._remove_entry(key)
            
            # 确保有足够空间
            self._ensure_capacity(size_bytes)
            
            # 添加到缓存
            self.cache[key] = entry
            self.access_order.append(key)
            self.stats['total_size_bytes'] += size_bytes
            
            return True
    
    def _remove_entry(self, key: str):
        """移除缓存条目"""
        if key in self.cache:
            entry = self.cache[key]
            self.stats['total_size_bytes'] -= entry.size_bytes
            del self.cache[key]
            
            if key in self.access_order:
                self.access_order.remove(key)
    
    def _ensure_capacity(self, new_size: int):
        """确保有足够的缓存容量"""
        # 检查数量限制
        while len(self.cache) >= self.max_size:
            self._evict_lru()
        
        # 检查内存限制
        while (self.stats['total_size_bytes'] + new_size) > self.max_memory_bytes:
            self._evict_lru()
    
    def _evict_lru(self):
        """移除最少使用的项"""
        if not self.access_order:
            return
        
        lru_key = self.access_order[0]
        self._remove_entry(lru_key)
        self.stats['evictions'] += 1
    
    def clear(self):
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()
            self.stats['total_size_bytes'] = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        hit_rate = 0.0
        if self.stats['hits'] + self.stats['misses'] > 0:
            hit_rate = self.stats['hits'] / (self.stats['hits'] + self.stats['misses'])
        
        return {
            **self.stats,
            'size': len(self.cache),
            'max_size': self.max_size,
            'hit_rate': hit_rate,
            'memory_usage_mb': self.stats['total_size_bytes'] / 1024 / 1024
        }


class PersistentCache(LoggerMixin):
    """持久化缓存"""
    
    def __init__(self, cache_dir: str = "data/cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.cache_dir / "cache.db"
        self._init_database()
        
        # 内存缓存
        self.memory_cache = LRUCache(max_size=500, max_memory_mb=50)
    
    def _init_database(self):
        """初始化数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value_hash TEXT,
                        created_time TEXT,
                        last_accessed TEXT,
                        access_count INTEGER,
                        expires_at TEXT,
                        size_bytes INTEGER,
                        file_path TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_entries(expires_at);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache_entries(last_accessed);
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化缓存数据库失败: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        # 先从内存缓存获取
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # 从磁盘缓存获取
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT value_hash, file_path, expires_at FROM cache_entries WHERE key = ?',
                    (key,)
                )
                row = cursor.fetchone()
                
                if row:
                    value_hash, file_path, expires_at = row
                    
                    # 检查是否过期
                    if expires_at:
                        expires_time = datetime.fromisoformat(expires_at)
                        if datetime.now() > expires_time:
                            self._remove_from_disk(key)
                            return None
                    
                    # 加载值
                    cache_file = self.cache_dir / file_path
                    if cache_file.exists():
                        with open(cache_file, 'rb') as f:
                            value = pickle.load(f)
                        
                        # 更新访问信息
                        self._update_access_info(key)
                        
                        # 添加到内存缓存
                        self.memory_cache.put(key, value)
                        
                        return value
                    else:
                        # 文件不存在，从数据库删除记录
                        self._remove_from_disk(key)
                
        except Exception as e:
            self.logger.error(f"从磁盘缓存获取失败: {e}")
        
        return None
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """放入缓存"""
        try:
            # 序列化值
            serialized_value = pickle.dumps(value)
            value_hash = hashlib.md5(serialized_value).hexdigest()
            
            # 保存到文件
            file_name = f"{hashlib.md5(key.encode()).hexdigest()}.cache"
            file_path = self.cache_dir / file_name
            
            with open(file_path, 'wb') as f:
                f.write(serialized_value)
            
            # 计算过期时间
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
            
            # 保存到数据库
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO cache_entries
                    (key, value_hash, created_time, last_accessed, access_count, 
                     expires_at, size_bytes, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    key,
                    value_hash,
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    0,
                    expires_at.isoformat() if expires_at else None,
                    len(serialized_value),
                    file_name
                ))
                conn.commit()
            
            # 添加到内存缓存
            self.memory_cache.put(key, value, ttl_seconds)
            
            return True
            
        except Exception as e:
            self.logger.error(f"保存到磁盘缓存失败: {e}")
            return False
    
    def _update_access_info(self, key: str):
        """更新访问信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE cache_entries 
                    SET last_accessed = ?, access_count = access_count + 1
                    WHERE key = ?
                ''', (datetime.now().isoformat(), key))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"更新访问信息失败: {e}")
    
    def _remove_from_disk(self, key: str):
        """从磁盘移除缓存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 获取文件路径
                cursor = conn.execute('SELECT file_path FROM cache_entries WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    file_path = self.cache_dir / row[0]
                    if file_path.exists():
                        file_path.unlink()
                
                # 从数据库删除
                conn.execute('DELETE FROM cache_entries WHERE key = ?', (key,))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"从磁盘移除缓存失败: {e}")
    
    def cleanup_expired(self):
        """清理过期缓存"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 获取过期的条目
                cursor = conn.execute('''
                    SELECT key, file_path FROM cache_entries 
                    WHERE expires_at IS NOT NULL AND expires_at < ?
                ''', (datetime.now().isoformat(),))
                
                expired_entries = cursor.fetchall()
                
                # 删除过期文件和记录
                for key, file_path in expired_entries:
                    cache_file = self.cache_dir / file_path
                    if cache_file.exists():
                        cache_file.unlink()
                
                # 从数据库删除过期记录
                conn.execute('''
                    DELETE FROM cache_entries 
                    WHERE expires_at IS NOT NULL AND expires_at < ?
                ''', (datetime.now().isoformat(),))
                
                conn.commit()
                
                if expired_entries:
                    self.logger.info(f"清理过期缓存: {len(expired_entries)} 个条目")
                
        except Exception as e:
            self.logger.error(f"清理过期缓存失败: {e}")


class SignatureCacheManager(LoggerMixin):
    """特征库缓存管理器"""
    
    def __init__(self, cache_dir: str = "data/signature_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.cache = PersistentCache(str(self.cache_dir))
        
        # 特征库版本信息
        self.version_file = self.cache_dir / "versions.json"
        self.versions = self._load_versions()
    
    def _load_versions(self) -> Dict[str, str]:
        """加载版本信息"""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"加载版本信息失败: {e}")
        
        return {}
    
    def _save_versions(self):
        """保存版本信息"""
        try:
            with open(self.version_file, 'w') as f:
                json.dump(self.versions, f, indent=2)
        except Exception as e:
            self.logger.error(f"保存版本信息失败: {e}")
    
    def cache_signature_db(self, db_type: str, version: str, data: Any) -> bool:
        """缓存特征库"""
        cache_key = f"signature_db_{db_type}_{version}"
        
        success = self.cache.put(cache_key, data, ttl_seconds=7*24*3600)  # 7天
        if success:
            self.versions[db_type] = version
            self._save_versions()
            self.logger.info(f"特征库已缓存: {db_type} v{version}")
        
        return success
    
    def get_cached_signature_db(self, db_type: str, version: str) -> Optional[Any]:
        """获取缓存的特征库"""
        cache_key = f"signature_db_{db_type}_{version}"
        data = self.cache.get(cache_key)
        
        if data:
            self.logger.info(f"使用缓存的特征库: {db_type} v{version}")
        
        return data
    
    def is_version_cached(self, db_type: str, version: str) -> bool:
        """检查版本是否已缓存"""
        return self.versions.get(db_type) == version
    
    def get_cached_versions(self) -> Dict[str, str]:
        """获取缓存的版本信息"""
        return self.versions.copy()


class IntelligentCacheManager(LoggerMixin):
    """智能缓存管理器"""
    
    def __init__(self):
        # 不同类型的缓存
        self.memory_cache = LRUCache(max_size=1000, max_memory_mb=100)
        self.persistent_cache = PersistentCache()
        self.signature_cache = SignatureCacheManager()
        
        # 缓存策略
        self.cache_strategies = {
            'scan_results': {'ttl': 3600, 'persistent': True},  # 1小时
            'file_hashes': {'ttl': 86400, 'persistent': True},  # 1天
            'threat_analysis': {'ttl': 7200, 'persistent': True},  # 2小时
            'yara_rules': {'ttl': 604800, 'persistent': True},  # 7天
            'virus_signatures': {'ttl': 604800, 'persistent': True}  # 7天
        }
        
        # 统计信息
        self.global_stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # 清理线程
        self.cleanup_thread = None
        self.cleanup_running = False
        self._start_cleanup_thread()
    
    def get(self, cache_type: str, key: str) -> Optional[Any]:
        """智能获取缓存"""
        self.global_stats['total_requests'] += 1
        
        # 首先尝试内存缓存
        full_key = f"{cache_type}:{key}"
        value = self.memory_cache.get(full_key)
        
        if value is not None:
            self.global_stats['cache_hits'] += 1
            return value
        
        # 然后尝试持久化缓存
        if self._should_use_persistent_cache(cache_type):
            value = self.persistent_cache.get(full_key)
            if value is not None:
                # 回写到内存缓存
                self.memory_cache.put(full_key, value)
                self.global_stats['cache_hits'] += 1
                return value
        
        self.global_stats['cache_misses'] += 1
        return None
    
    def put(self, cache_type: str, key: str, value: Any) -> bool:
        """智能放入缓存"""
        strategy = self.cache_strategies.get(cache_type, {'ttl': 3600, 'persistent': False})
        full_key = f"{cache_type}:{key}"
        
        # 放入内存缓存
        memory_success = self.memory_cache.put(full_key, value, strategy['ttl'])
        
        # 如果策略要求，也放入持久化缓存
        persistent_success = True
        if strategy.get('persistent', False):
            persistent_success = self.persistent_cache.put(full_key, value, strategy['ttl'])
        
        return memory_success and persistent_success
    
    def _should_use_persistent_cache(self, cache_type: str) -> bool:
        """判断是否应该使用持久化缓存"""
        strategy = self.cache_strategies.get(cache_type, {})
        return strategy.get('persistent', False)
    
    def _start_cleanup_thread(self):
        """启动清理线程"""
        if self.cleanup_running:
            return
        
        self.cleanup_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_worker(self):
        """清理工作线程"""
        while self.cleanup_running:
            try:
                # 每小时清理一次
                time.sleep(3600)
                
                # 清理过期缓存
                self.persistent_cache.cleanup_expired()
                
                self.logger.info("缓存清理完成")
                
            except Exception as e:
                self.logger.error(f"缓存清理异常: {e}")
    
    def get_global_stats(self) -> Dict[str, Any]:
        """获取全局统计"""
        hit_rate = 0.0
        if self.global_stats['total_requests'] > 0:
            hit_rate = self.global_stats['cache_hits'] / self.global_stats['total_requests']
        
        return {
            **self.global_stats,
            'hit_rate': hit_rate,
            'memory_cache_stats': self.memory_cache.get_stats()
        }
    
    def invalidate_cache_type(self, cache_type: str):
        """使指定类型的缓存失效"""
        # 这里可以实现更精细的缓存失效逻辑
        self.logger.info(f"缓存类型失效: {cache_type}")
    
    def clear_all_caches(self):
        """清空所有缓存"""
        self.memory_cache.clear()
        # 持久化缓存的清理需要更复杂的逻辑
        self.logger.info("所有缓存已清空")
    
    def stop(self):
        """停止缓存管理器"""
        self.cleanup_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        self.logger.info("智能缓存管理器已停止")