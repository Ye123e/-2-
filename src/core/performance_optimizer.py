#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能优化模块 - 多线程并发、内存管理、算法优化
"""

import os
import gc
import psutil
import threading
import time
import queue
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import hashlib

from ..utils.logger import LoggerMixin


class MemoryManager(LoggerMixin):
    """内存管理器"""
    
    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_mb = max_memory_mb
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.memory_threshold = 0.85  # 内存使用率阈值
        self.monitor_thread = None
        self.monitoring = False
        
        # 内存统计
        self.stats = {
            'peak_memory_mb': 0,
            'gc_collections': 0,
            'memory_warnings': 0,
            'cache_evictions': 0
        }
    
    def start_monitoring(self):
        """开始内存监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_memory, daemon=True)
        self.monitor_thread.start()
        self.logger.info("内存监控已启动")
    
    def stop_monitoring(self):
        """停止内存监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("内存监控已停止")
    
    def _monitor_memory(self):
        """内存监控主循环"""
        while self.monitoring:
            try:
                current_memory = self.get_current_memory_usage()
                
                # 更新峰值内存
                if current_memory > self.stats['peak_memory_mb']:
                    self.stats['peak_memory_mb'] = current_memory
                
                # 检查内存使用率
                if current_memory > self.max_memory_mb * self.memory_threshold:
                    self.stats['memory_warnings'] += 1
                    self._handle_high_memory()
                
                time.sleep(5)  # 每5秒检查一次
                
            except Exception as e:
                self.logger.error(f"内存监控异常: {e}")
                time.sleep(10)
    
    def get_current_memory_usage(self) -> float:
        """获取当前内存使用量(MB)"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / 1024 / 1024
        except Exception as e:
            self.logger.error(f"获取内存使用量失败: {e}")
            return 0.0
    
    def _handle_high_memory(self):
        """处理高内存使用"""
        self.logger.warning(f"内存使用过高: {self.get_current_memory_usage():.1f}MB")
        
        # 执行垃圾回收
        collected = gc.collect()
        self.stats['gc_collections'] += 1
        
        self.logger.info(f"垃圾回收完成，回收对象: {collected}")
        
        # 清理缓存（如果有的话）
        self._cleanup_caches()
    
    def _cleanup_caches(self):
        """清理缓存"""
        # 这里可以实现具体的缓存清理逻辑
        self.stats['cache_evictions'] += 1
        self.logger.info("缓存清理完成")
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """获取内存统计信息"""
        return {
            **self.stats,
            'current_memory_mb': self.get_current_memory_usage(),
            'max_memory_mb': self.max_memory_mb,
            'memory_threshold': self.memory_threshold
        }


class ThreadPoolManager(LoggerMixin):
    """线程池管理器"""
    
    def __init__(self, max_workers: int = None):
        if max_workers is None:
            max_workers = min(32, (os.cpu_count() or 1) + 4)
        
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks = {}
        self.task_counter = 0
        
        # 统计信息
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'average_task_time': 0.0
        }
    
    def submit_task(self, func: Callable, *args, **kwargs) -> str:
        """提交任务到线程池"""
        task_id = f"task_{self.task_counter}"
        self.task_counter += 1
        
        future = self.executor.submit(self._execute_task, func, task_id, *args, **kwargs)
        self.active_tasks[task_id] = {
            'future': future,
            'start_time': time.time(),
            'function': func.__name__
        }
        
        self.stats['total_tasks'] += 1
        return task_id
    
    def _execute_task(self, func: Callable, task_id: str, *args, **kwargs):
        """执行任务"""
        try:
            start_time = time.time()
            result = func(*args, **kwargs)
            
            # 更新统计
            execution_time = time.time() - start_time
            self._update_task_stats(task_id, execution_time, True)
            
            return result
            
        except Exception as e:
            self._update_task_stats(task_id, 0, False)
            self.logger.error(f"任务执行失败 {task_id}: {e}")
            raise
        finally:
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]
    
    def _update_task_stats(self, task_id: str, execution_time: float, success: bool):
        """更新任务统计"""
        if success:
            self.stats['completed_tasks'] += 1
            # 更新平均执行时间
            total_time = self.stats['average_task_time'] * (self.stats['completed_tasks'] - 1)
            self.stats['average_task_time'] = (total_time + execution_time) / self.stats['completed_tasks']
        else:
            self.stats['failed_tasks'] += 1
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """等待所有任务完成"""
        try:
            futures = [task['future'] for task in self.active_tasks.values()]
            for future in as_completed(futures, timeout=timeout):
                pass
            return True
        except Exception as e:
            self.logger.error(f"等待任务完成失败: {e}")
            return False
    
    def get_thread_stats(self) -> Dict[str, Any]:
        """获取线程池统计"""
        return {
            **self.stats,
            'max_workers': self.max_workers,
            'active_tasks': len(self.active_tasks)
        }
    
    def shutdown(self):
        """关闭线程池"""
        self.executor.shutdown(wait=True)
        self.logger.info("线程池已关闭")


class ScanOptimizer(LoggerMixin):
    """扫描优化器"""
    
    def __init__(self, thread_manager: ThreadPoolManager, memory_manager: MemoryManager):
        self.thread_manager = thread_manager
        self.memory_manager = memory_manager
        
        # 优化参数
        self.batch_size = 100  # 批处理大小
        self.max_file_size = 50 * 1024 * 1024  # 最大文件大小 50MB
        self.skip_extensions = {'.tmp', '.log', '.cache', '.bak'}
        
        # 文件类型优先级
        self.priority_extensions = {
            '.apk': 10,
            '.dex': 9,
            '.so': 8,
            '.jar': 7,
            '.exe': 6
        }
    
    def optimize_file_list(self, file_paths: List[str]) -> List[str]:
        """优化文件列表"""
        # 过滤掉不需要扫描的文件
        filtered_files = []
        
        for file_path in file_paths:
            if self._should_scan_file(file_path):
                filtered_files.append(file_path)
        
        # 按优先级排序
        filtered_files.sort(key=self._get_file_priority, reverse=True)
        
        self.logger.info(f"文件列表优化: {len(file_paths)} -> {len(filtered_files)}")
        return filtered_files
    
    def _should_scan_file(self, file_path: str) -> bool:
        """判断是否应该扫描文件"""
        try:
            path_obj = Path(file_path)
            
            # 检查文件扩展名
            if path_obj.suffix.lower() in self.skip_extensions:
                return False
            
            # 检查文件大小
            if path_obj.exists() and path_obj.stat().st_size > self.max_file_size:
                return False
            
            # 检查是否为隐藏文件或系统文件
            if path_obj.name.startswith('.'):
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"检查文件失败 {file_path}: {e}")
            return False
    
    def _get_file_priority(self, file_path: str) -> int:
        """获取文件扫描优先级"""
        ext = Path(file_path).suffix.lower()
        return self.priority_extensions.get(ext, 1)
    
    def batch_scan_files(self, file_paths: List[str], scan_function: Callable) -> List[Any]:
        """批量扫描文件"""
        results = []
        
        # 优化文件列表
        optimized_files = self.optimize_file_list(file_paths)
        
        # 分批处理
        batches = [optimized_files[i:i + self.batch_size] 
                  for i in range(0, len(optimized_files), self.batch_size)]
        
        for batch_idx, batch in enumerate(batches):
            # 检查内存使用
            if self.memory_manager.get_current_memory_usage() > self.memory_manager.max_memory_mb * 0.9:
                self.logger.warning("内存使用过高，暂停扫描")
                time.sleep(2)
                gc.collect()
            
            # 提交批处理任务
            batch_results = self._scan_batch(batch, scan_function)
            results.extend(batch_results)
            
            self.logger.debug(f"完成批次 {batch_idx + 1}/{len(batches)}")
        
        return results
    
    def _scan_batch(self, file_batch: List[str], scan_function: Callable) -> List[Any]:
        """扫描一批文件"""
        batch_results = []
        
        # 为批次中的每个文件提交任务
        task_futures = {}
        for file_path in file_batch:
            task_id = self.thread_manager.submit_task(scan_function, file_path)
            task_futures[task_id] = file_path
        
        # 收集结果
        for task_id, file_path in task_futures.items():
            try:
                task_info = self.thread_manager.active_tasks.get(task_id)
                if task_info:
                    result = task_info['future'].result(timeout=30)
                    if result:
                        batch_results.append(result)
            except Exception as e:
                self.logger.error(f"扫描文件失败 {file_path}: {e}")
        
        return batch_results


class CacheManager(LoggerMixin):
    """缓存管理器"""
    
    def __init__(self, cache_size_mb: int = 100):
        self.cache_size_mb = cache_size_mb
        self.cache_size_bytes = cache_size_mb * 1024 * 1024
        
        # 哈希缓存
        self.file_hash_cache: Dict[str, Dict] = {}
        
        # 扫描结果缓存
        self.scan_result_cache: Dict[str, Dict] = {}
        
        # 缓存访问时间
        self.access_times: Dict[str, float] = {}
        
        # 统计信息
        self.stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'cache_evictions': 0,
            'total_cached_items': 0
        }
    
    def get_file_hash(self, file_path: str, force_recalculate: bool = False) -> Optional[str]:
        """获取文件哈希值"""
        cache_key = f"hash_{file_path}"
        
        if not force_recalculate and cache_key in self.file_hash_cache:
            # 检查文件是否已修改
            cached_info = self.file_hash_cache[cache_key]
            try:
                current_mtime = os.path.getmtime(file_path)
                if current_mtime == cached_info['mtime']:
                    self.stats['cache_hits'] += 1
                    self.access_times[cache_key] = time.time()
                    return cached_info['hash']
            except OSError:
                pass
        
        # 计算新的哈希值
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash:
                self._cache_file_hash(file_path, file_hash)
                self.stats['cache_misses'] += 1
            return file_hash
        except Exception as e:
            self.logger.error(f"计算文件哈希失败 {file_path}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """计算文件哈希值"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.debug(f"计算哈希失败 {file_path}: {e}")
            return None
    
    def _cache_file_hash(self, file_path: str, file_hash: str):
        """缓存文件哈希值"""
        cache_key = f"hash_{file_path}"
        
        try:
            mtime = os.path.getmtime(file_path)
            self.file_hash_cache[cache_key] = {
                'hash': file_hash,
                'mtime': mtime,
                'size': os.path.getsize(file_path)
            }
            self.access_times[cache_key] = time.time()
            self.stats['total_cached_items'] += 1
            
            # 检查缓存大小并清理
            self._cleanup_cache_if_needed()
            
        except OSError as e:
            self.logger.debug(f"缓存文件哈希失败 {file_path}: {e}")
    
    def cache_scan_result(self, file_path: str, result: Dict):
        """缓存扫描结果"""
        cache_key = f"scan_{file_path}"
        
        self.scan_result_cache[cache_key] = {
            'result': result,
            'timestamp': time.time()
        }
        self.access_times[cache_key] = time.time()
    
    def get_cached_scan_result(self, file_path: str, max_age_seconds: int = 3600) -> Optional[Dict]:
        """获取缓存的扫描结果"""
        cache_key = f"scan_{file_path}"
        
        if cache_key in self.scan_result_cache:
            cached_data = self.scan_result_cache[cache_key]
            
            # 检查缓存是否过期
            if time.time() - cached_data['timestamp'] < max_age_seconds:
                self.stats['cache_hits'] += 1
                self.access_times[cache_key] = time.time()
                return cached_data['result']
            else:
                # 删除过期缓存
                del self.scan_result_cache[cache_key]
                if cache_key in self.access_times:
                    del self.access_times[cache_key]
        
        self.stats['cache_misses'] += 1
        return None
    
    def _cleanup_cache_if_needed(self):
        """必要时清理缓存"""
        # 简化的缓存清理：删除最旧的项目
        if len(self.file_hash_cache) + len(self.scan_result_cache) > 1000:
            self._evict_oldest_items(100)
    
    def _evict_oldest_items(self, count: int):
        """清除最旧的缓存项"""
        # 按访问时间排序
        sorted_items = sorted(self.access_times.items(), key=lambda x: x[1])
        
        evicted = 0
        for cache_key, _ in sorted_items[:count]:
            if cache_key.startswith('hash_'):
                self.file_hash_cache.pop(cache_key, None)
            elif cache_key.startswith('scan_'):
                self.scan_result_cache.pop(cache_key, None)
            
            self.access_times.pop(cache_key, None)
            evicted += 1
        
        self.stats['cache_evictions'] += evicted
        self.logger.debug(f"清理缓存项: {evicted}")
    
    def clear_cache(self):
        """清空所有缓存"""
        self.file_hash_cache.clear()
        self.scan_result_cache.clear()
        self.access_times.clear()
        self.logger.info("缓存已清空")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        total_items = len(self.file_hash_cache) + len(self.scan_result_cache)
        hit_rate = 0.0
        if self.stats['cache_hits'] + self.stats['cache_misses'] > 0:
            hit_rate = self.stats['cache_hits'] / (self.stats['cache_hits'] + self.stats['cache_misses'])
        
        return {
            **self.stats,
            'total_items': total_items,
            'hash_cache_items': len(self.file_hash_cache),
            'scan_cache_items': len(self.scan_result_cache),
            'cache_hit_rate': hit_rate,
            'cache_size_mb': self.cache_size_mb
        }


class PerformanceOptimizer(LoggerMixin):
    """性能优化器主类"""
    
    def __init__(self, max_memory_mb: int = 512, max_workers: int = None, cache_size_mb: int = 100):
        self.memory_manager = MemoryManager(max_memory_mb)
        self.thread_manager = ThreadPoolManager(max_workers)
        self.cache_manager = CacheManager(cache_size_mb)
        self.scan_optimizer = ScanOptimizer(self.thread_manager, self.memory_manager)
        
        # 性能监控
        self.performance_metrics = {
            'scan_start_time': None,
            'files_processed': 0,
            'throughput_files_per_second': 0.0
        }
    
    def start_optimization(self):
        """启动性能优化"""
        self.memory_manager.start_monitoring()
        self.logger.info("性能优化已启动")
    
    def stop_optimization(self):
        """停止性能优化"""
        self.memory_manager.stop_monitoring()
        self.thread_manager.shutdown()
        self.logger.info("性能优化已停止")
    
    def optimize_scan(self, file_paths: List[str], scan_function: Callable) -> List[Any]:
        """优化扫描过程"""
        self.performance_metrics['scan_start_time'] = time.time()
        self.performance_metrics['files_processed'] = 0
        
        # 使用优化的扫描器
        results = self.scan_optimizer.batch_scan_files(file_paths, self._enhanced_scan_function(scan_function))
        
        # 计算吞吐量
        elapsed_time = time.time() - self.performance_metrics['scan_start_time']
        if elapsed_time > 0:
            self.performance_metrics['throughput_files_per_second'] = len(file_paths) / elapsed_time
        
        return results
    
    def _enhanced_scan_function(self, original_scan_function: Callable) -> Callable:
        """增强的扫描函数"""
        def enhanced_scan(file_path: str):
            try:
                # 检查缓存
                cached_result = self.cache_manager.get_cached_scan_result(file_path)
                if cached_result:
                    return cached_result
                
                # 执行原始扫描
                result = original_scan_function(file_path)
                
                # 缓存结果
                if result:
                    self.cache_manager.cache_scan_result(file_path, result)
                
                # 更新性能指标
                self.performance_metrics['files_processed'] += 1
                
                return result
                
            except Exception as e:
                self.logger.error(f"增强扫描失败 {file_path}: {e}")
                return None
        
        return enhanced_scan
    
    def get_performance_report(self) -> Dict[str, Any]:
        """获取性能报告"""
        return {
            'memory_stats': self.memory_manager.get_memory_stats(),
            'thread_stats': self.thread_manager.get_thread_stats(),
            'cache_stats': self.cache_manager.get_cache_stats(),
            'performance_metrics': self.performance_metrics.copy()
        }