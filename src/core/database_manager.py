#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库管理系统 - SQLite本地存储、数据缓存、索引优化
"""

import sqlite3
import json
import threading
import time
from typing import List, Dict, Optional, Any, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

from ..utils.logger import LoggerMixin
from ..models import *


class DatabasePool:
    """数据库连接池"""
    
    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = []
        self.in_use = set()
        self.lock = threading.Lock()
    
    def get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        with self.lock:
            # 查找可用连接
            for conn in self.connections:
                if conn not in self.in_use:
                    self.in_use.add(conn)
                    return conn
            
            # 创建新连接
            if len(self.connections) < self.max_connections:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                self.connections.append(conn)
                self.in_use.add(conn)
                return conn
            
            # 等待可用连接
            while True:
                for conn in self.connections:
                    if conn not in self.in_use:
                        self.in_use.add(conn)
                        return conn
                time.sleep(0.1)
    
    def release_connection(self, conn: sqlite3.Connection):
        """释放数据库连接"""
        with self.lock:
            self.in_use.discard(conn)
    
    def close_all(self):
        """关闭所有连接"""
        with self.lock:
            for conn in self.connections:
                conn.close()
            self.connections.clear()
            self.in_use.clear()


class CacheManager:
    """缓存管理器"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Any] = {}
        self.access_times: Dict[str, datetime] = {}
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存数据"""
        with self.lock:
            if key not in self.cache:
                return None
            
            # 检查TTL
            if datetime.now() - self.access_times[key] > timedelta(seconds=self.ttl_seconds):
                del self.cache[key]
                del self.access_times[key]
                return None
            
            self.access_times[key] = datetime.now()
            return self.cache[key]
    
    def set(self, key: str, value: Any):
        """设置缓存数据"""
        with self.lock:
            # 清理过期缓存
            self._cleanup_expired()
            
            # 如果缓存满了，删除最旧的项
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
                del self.cache[oldest_key]
                del self.access_times[oldest_key]
            
            self.cache[key] = value
            self.access_times[key] = datetime.now()
    
    def delete(self, key: str):
        """删除缓存数据"""
        with self.lock:
            self.cache.pop(key, None)
            self.access_times.pop(key, None)
    
    def clear(self):
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
    
    def _cleanup_expired(self):
        """清理过期缓存"""
        current_time = datetime.now()
        expired_keys = []
        
        for key, access_time in self.access_times.items():
            if current_time - access_time > timedelta(seconds=self.ttl_seconds):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
            del self.access_times[key]


class DatabaseManager(LoggerMixin):
    """数据库管理器主类"""
    
    def __init__(self, db_path: str = "data/security_database.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 连接池和缓存
        self.pool = DatabasePool(str(self.db_path))
        self.cache = CacheManager()
        
        # 统计信息
        self.stats = {
            'queries_executed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'db_size_mb': 0
        }
        
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """获取数据库连接上下文管理器"""
        conn = self.pool.get_connection()
        try:
            yield conn
        finally:
            self.pool.release_connection(conn)
    
    def _init_database(self):
        """初始化数据库表结构"""
        with self.get_connection() as conn:
            try:
                # 设备信息表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS devices (
                        device_id TEXT PRIMARY KEY,
                        model TEXT,
                        android_version TEXT,
                        build_number TEXT,
                        root_status BOOLEAN,
                        storage_total INTEGER,
                        storage_free INTEGER,
                        connection_type TEXT,
                        last_connected TEXT,
                        manufacturer TEXT,
                        cpu_arch TEXT,
                        screen_resolution TEXT,
                        created_time TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_time TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # 扫描结果表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        scan_id TEXT PRIMARY KEY,
                        device_id TEXT,
                        scan_mode TEXT,
                        start_time TEXT,
                        end_time TEXT,
                        status TEXT,
                        total_files_scanned INTEGER,
                        threats_found INTEGER,
                        vulnerabilities_found INTEGER,
                        scan_paths TEXT,
                        excluded_paths TEXT,
                        scan_summary TEXT,
                        performance_stats TEXT,
                        metadata TEXT,
                        FOREIGN KEY (device_id) REFERENCES devices (device_id)
                    )
                ''')
                
                # 恶意软件信息表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS malware_info (
                        threat_id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        threat_name TEXT,
                        package_name TEXT,
                        file_path TEXT,
                        threat_type TEXT,
                        threat_level TEXT,
                        engine_type TEXT,
                        confidence REAL,
                        file_hash TEXT,
                        file_size INTEGER,
                        signature_match TEXT,
                        first_seen TEXT,
                        last_updated TEXT,
                        description TEXT,
                        metadata TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                    )
                ''')
                
                # 安全事件表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT,
                        timestamp TEXT,
                        device_id TEXT,
                        source TEXT,
                        threat_level TEXT,
                        action_taken TEXT,
                        description TEXT,
                        details TEXT,
                        FOREIGN KEY (device_id) REFERENCES devices (device_id)
                    )
                ''')
                
                self._create_indexes(conn)
                conn.commit()
                
                self.logger.info("数据库初始化完成")
                
            except Exception as e:
                self.logger.error(f"数据库初始化失败: {e}")
                conn.rollback()
                raise
    
    def _create_indexes(self, conn: sqlite3.Connection):
        """创建数据库索引"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_devices_model ON devices(model)",
            "CREATE INDEX IF NOT EXISTS idx_scan_results_device_id ON scan_results(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_results_start_time ON scan_results(start_time)",
            "CREATE INDEX IF NOT EXISTS idx_malware_threat_level ON malware_info(threat_level)",
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)",
        ]
        
        for index_sql in indexes:
            try:
                conn.execute(index_sql)
            except Exception as e:
                self.logger.warning(f"创建索引失败: {e}")
    
    def insert_device(self, device: DeviceInfo) -> bool:
        """插入设备信息"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO devices 
                    (device_id, model, android_version, build_number, root_status,
                     storage_total, storage_free, connection_type, last_connected,
                     manufacturer, cpu_arch, screen_resolution, updated_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device.device_id, device.model, device.android_version,
                    device.build_number, device.root_status, device.storage_total,
                    device.storage_free, device.connection_type.value,
                    device.last_connected.isoformat() if device.last_connected else None,
                    device.manufacturer, device.cpu_arch, device.screen_resolution,
                    datetime.now().isoformat()
                ))
                conn.commit()
                
                # 清除相关缓存
                self.cache.delete(f"device_{device.device_id}")
                
                self.stats['queries_executed'] += 1
                return True
                
        except Exception as e:
            self.logger.error(f"插入设备信息失败: {e}")
            return False
    
    def get_device(self, device_id: str) -> Optional[DeviceInfo]:
        """获取设备信息"""
        cache_key = f"device_{device_id}"
        
        # 先检查缓存
        cached_device = self.cache.get(cache_key)
        if cached_device:
            self.stats['cache_hits'] += 1
            return cached_device
        
        self.stats['cache_misses'] += 1
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    'SELECT * FROM devices WHERE device_id = ?', 
                    (device_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    device = DeviceInfo(
                        device_id=row['device_id'],
                        model=row['model'] or '',
                        android_version=row['android_version'] or '',
                        build_number=row['build_number'] or '',
                        root_status=bool(row['root_status']),
                        storage_total=row['storage_total'] or 0,
                        storage_free=row['storage_free'] or 0,
                        connection_type=ConnectionType(row['connection_type']) if row['connection_type'] else ConnectionType.UNKNOWN,
                        last_connected=datetime.fromisoformat(row['last_connected']) if row['last_connected'] else None,
                        manufacturer=row['manufacturer'] or '',
                        cpu_arch=row['cpu_arch'] or '',
                        screen_resolution=row['screen_resolution'] or ''
                    )
                    
                    # 加入缓存
                    self.cache.set(cache_key, device)
                    self.stats['queries_executed'] += 1
                    return device
                
        except Exception as e:
            self.logger.error(f"获取设备信息失败: {e}")
        
        return None
    
    def insert_scan_result(self, scan_result: ScanResult) -> bool:
        """插入扫描结果"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO scan_results 
                    (scan_id, device_id, scan_mode, start_time, end_time, status,
                     total_files_scanned, threats_found, vulnerabilities_found,
                     scan_paths, excluded_paths, scan_summary, performance_stats, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result.scan_id, scan_result.device_id, scan_result.scan_mode.value,
                    scan_result.start_time.isoformat(),
                    scan_result.end_time.isoformat() if scan_result.end_time else None,
                    scan_result.status, scan_result.total_files_scanned,
                    scan_result.threats_found, scan_result.vulnerabilities_found,
                    json.dumps(scan_result.scan_paths),
                    json.dumps(scan_result.excluded_paths),
                    scan_result.scan_summary,
                    json.dumps(scan_result.performance_stats),
                    json.dumps(scan_result.metadata)
                ))
                
                # 插入关联的恶意软件信息
                for malware in scan_result.malware_list:
                    self._insert_malware_info(malware, scan_result.scan_id, conn)
                
                conn.commit()
                self.stats['queries_executed'] += 1
                return True
                
        except Exception as e:
            self.logger.error(f"插入扫描结果失败: {e}")
            return False
    
    def _insert_malware_info(self, malware: MalwareInfo, scan_id: str, conn: sqlite3.Connection):
        """插入恶意软件信息"""
        conn.execute('''
            INSERT OR REPLACE INTO malware_info
            (threat_id, scan_id, threat_name, package_name, file_path,
             threat_type, threat_level, engine_type, confidence, file_hash,
             file_size, signature_match, first_seen, last_updated,
             description, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            malware.threat_id, scan_id, malware.threat_name,
            malware.package_name, malware.file_path,
            malware.threat_type.value, malware.threat_level.value,
            malware.engine_type.value, malware.confidence,
            malware.file_hash, malware.file_size, malware.signature_match,
            malware.first_seen.isoformat() if malware.first_seen else None,
            malware.last_updated.isoformat() if malware.last_updated else None,
            malware.description, json.dumps(malware.metadata)
        ))
    
    def insert_security_event(self, event: SecurityEvent) -> bool:
        """插入安全事件"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO security_events
                    (event_id, event_type, timestamp, device_id, source,
                     threat_level, action_taken, description, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id, event.event_type, 
                    event.timestamp.isoformat(), event.device_id,
                    event.source, event.threat_level.value,
                    event.action_taken, event.description,
                    json.dumps(event.details)
                ))
                conn.commit()
                
                self.stats['queries_executed'] += 1
                return True
                
        except Exception as e:
            self.logger.error(f"插入安全事件失败: {e}")
            return False
    
    def get_security_events(self, device_id: str = None, limit: int = 100) -> List[SecurityEvent]:
        """获取安全事件列表"""
        try:
            with self.get_connection() as conn:
                if device_id:
                    cursor = conn.execute('''
                        SELECT * FROM security_events 
                        WHERE device_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (device_id, limit))
                else:
                    cursor = conn.execute('''
                        SELECT * FROM security_events 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (limit,))
                
                events = []
                for row in cursor:
                    event = SecurityEvent(
                        event_id=row['event_id'],
                        event_type=row['event_type'],
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        device_id=row['device_id'],
                        source=row['source'],
                        threat_level=ThreatLevel(row['threat_level']),
                        action_taken=row['action_taken'],
                        description=row['description'],
                        details=json.loads(row['details']) if row['details'] else {}
                    )
                    events.append(event)
                
                self.stats['queries_executed'] += 1
                return events
                
        except Exception as e:
            self.logger.error(f"获取安全事件失败: {e}")
            return []
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """清理旧数据"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            cutoff_str = cutoff_date.isoformat()
            
            with self.get_connection() as conn:
                # 清理旧的安全事件
                conn.execute(
                    'DELETE FROM security_events WHERE timestamp < ?', 
                    (cutoff_str,)
                )
                
                # 清理旧的扫描结果
                conn.execute(
                    'DELETE FROM scan_results WHERE start_time < ?', 
                    (cutoff_str,)
                )
                
                conn.commit()
                
                # 清空缓存
                self.cache.clear()
                
                self.logger.info(f"清理了{days_to_keep}天前的旧数据")
                
        except Exception as e:
            self.logger.error(f"清理旧数据失败: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取数据库统计信息"""
        try:
            # 计算数据库文件大小
            if self.db_path.exists():
                self.stats['db_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
            
            with self.get_connection() as conn:
                # 获取表记录数
                table_counts = {}
                tables = ['devices', 'scan_results', 'malware_info', 'security_events']
                
                for table in tables:
                    cursor = conn.execute(f'SELECT COUNT(*) FROM {table}')
                    table_counts[table] = cursor.fetchone()[0]
                
                self.stats['table_counts'] = table_counts
                
            return self.stats.copy()
            
        except Exception as e:
            self.logger.error(f"获取统计信息失败: {e}")
            return self.stats.copy()
    
    def close(self):
        """关闭数据库管理器"""
        self.pool.close_all()
        self.cache.clear()
        self.logger.info("数据库管理器已关闭")