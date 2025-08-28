#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
应用健康监控系统
实时监控应用状态，预防闪退问题
"""

import os
import sys
import time
import threading
import psutil
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import queue
import gc
from pathlib import Path

class HealthStatus(Enum):
    """健康状态枚举"""
    EXCELLENT = "excellent"      # 优秀
    GOOD = "good"               # 良好
    WARNING = "warning"         # 警告
    CRITICAL = "critical"       # 严重
    UNKNOWN = "unknown"         # 未知

@dataclass
class HealthMetric:
    """健康指标"""
    name: str
    value: float
    threshold_warning: float
    threshold_critical: float
    unit: str
    description: str
    last_updated: float = field(default_factory=time.time)

@dataclass
class HealthAlert:
    """健康警报"""
    metric_name: str
    severity: HealthStatus
    message: str
    timestamp: float
    resolved: bool = False
    auto_fix_attempted: bool = False

class SystemHealthMonitor:
    """系统健康监控器"""
    
    def __init__(self, check_interval: float = 30.0):
        """
        初始化系统健康监控器
        
        Args:
            check_interval: 检查间隔（秒）
        """
        self.check_interval = check_interval
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.monitoring_thread = None
        
        # 健康指标
        self.metrics: Dict[str, HealthMetric] = {}
        self.alerts: List[HealthAlert] = []
        self.alert_queue = queue.Queue()
        
        # 回调函数
        self.alert_callbacks: List[Callable[[HealthAlert], None]] = []
        
        # 初始化监控指标
        self._initialize_metrics()
        
        # 进程信息
        self.process = psutil.Process()
        self.start_time = time.time()
    
    def _initialize_metrics(self):
        """初始化监控指标"""
        self.metrics = {
            'memory_usage': HealthMetric(
                name="内存使用率",
                value=0.0,
                threshold_warning=80.0,
                threshold_critical=95.0,
                unit="%",
                description="应用程序内存使用百分比"
            ),
            'cpu_usage': HealthMetric(
                name="CPU使用率",
                value=0.0,
                threshold_warning=70.0,
                threshold_critical=90.0,
                unit="%",
                description="应用程序CPU使用百分比"
            ),
            'disk_usage': HealthMetric(
                name="磁盘使用率",
                value=0.0,
                threshold_warning=85.0,
                threshold_critical=95.0,
                unit="%",
                description="磁盘空间使用百分比"
            ),
            'thread_count': HealthMetric(
                name="线程数量",
                value=0.0,
                threshold_warning=50.0,
                threshold_critical=100.0,
                unit="个",
                description="应用程序线程数量"
            ),
            'file_handles': HealthMetric(
                name="文件句柄数",
                value=0.0,
                threshold_warning=500.0,
                threshold_critical=1000.0,
                unit="个",
                description="打开的文件句柄数量"
            ),
            'response_time': HealthMetric(
                name="响应时间",
                value=0.0,
                threshold_warning=2000.0,
                threshold_critical=5000.0,
                unit="ms",
                description="GUI响应时间"
            ),
            'error_rate': HealthMetric(
                name="错误率",
                value=0.0,
                threshold_warning=5.0,
                threshold_critical=10.0,
                unit="%",
                description="每分钟错误发生率"
            )
        }
    
    def start_monitoring(self):
        """开始监控"""
        if self.is_running:
            self.logger.warning("健康监控已在运行")
            return
        
        self.is_running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("健康监控已启动")
    
    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5.0)
        self.logger.info("健康监控已停止")
    
    def _monitoring_loop(self):
        """监控循环"""
        while self.is_running:
            try:
                # 收集指标
                self._collect_metrics()
                
                # 检查健康状态
                self._check_health()
                
                # 处理警报
                self._process_alerts()
                
                # 等待下次检查
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"健康监控循环异常: {e}")
                time.sleep(self.check_interval)
    
    def _collect_metrics(self):
        """收集性能指标"""
        try:
            current_time = time.time()
            
            # 内存使用率
            memory_info = self.process.memory_info()
            system_memory = psutil.virtual_memory()
            memory_percent = (memory_info.rss / system_memory.total) * 100
            self.metrics['memory_usage'].value = memory_percent
            self.metrics['memory_usage'].last_updated = current_time
            
            # CPU使用率
            cpu_percent = self.process.cpu_percent()
            self.metrics['cpu_usage'].value = cpu_percent
            self.metrics['cpu_usage'].last_updated = current_time
            
            # 磁盘使用率
            disk_usage = psutil.disk_usage('.')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            self.metrics['disk_usage'].value = disk_percent
            self.metrics['disk_usage'].last_updated = current_time
            
            # 线程数量
            thread_count = self.process.num_threads()
            self.metrics['thread_count'].value = thread_count
            self.metrics['thread_count'].last_updated = current_time
            
            # 文件句柄数（Windows和Linux不同）
            try:
                if hasattr(self.process, 'num_fds'):
                    file_handles = self.process.num_fds()  # Linux
                else:
                    file_handles = self.process.num_handles()  # Windows
                self.metrics['file_handles'].value = file_handles
                self.metrics['file_handles'].last_updated = current_time
            except (AttributeError, psutil.AccessDenied):
                # 某些系统可能无法访问此信息
                pass
            
            # 运行时间相关指标
            uptime = current_time - self.start_time
            
            # 简单的响应时间测试（通过线程数变化来估算）
            # 这是一个简化的实现，实际应用中可能需要更复杂的测量
            response_time = min(1000 + (thread_count * 10), 5000)
            self.metrics['response_time'].value = response_time
            self.metrics['response_time'].last_updated = current_time
            
        except Exception as e:
            self.logger.error(f"收集性能指标失败: {e}")
    
    def _check_health(self):
        """检查健康状态"""
        for metric_name, metric in self.metrics.items():
            # 检查是否超过阈值
            if metric.value >= metric.threshold_critical:
                self._create_alert(metric_name, HealthStatus.CRITICAL, 
                                 f"{metric.name}达到严重水平: {metric.value:.1f}{metric.unit}")
            elif metric.value >= metric.threshold_warning:
                self._create_alert(metric_name, HealthStatus.WARNING,
                                 f"{metric.name}达到警告水平: {metric.value:.1f}{metric.unit}")
    
    def _create_alert(self, metric_name: str, severity: HealthStatus, message: str):
        """创建警报"""
        # 检查是否已存在相同的未解决警报
        existing_alert = next(
            (alert for alert in self.alerts 
             if alert.metric_name == metric_name and not alert.resolved),
            None
        )
        
        if existing_alert:
            # 更新现有警报
            existing_alert.severity = severity
            existing_alert.message = message
            existing_alert.timestamp = time.time()
        else:
            # 创建新警报
            alert = HealthAlert(
                metric_name=metric_name,
                severity=severity,
                message=message,
                timestamp=time.time()
            )
            self.alerts.append(alert)
            self.alert_queue.put(alert)
            
            self.logger.warning(f"健康警报: {message}")
    
    def _process_alerts(self):
        """处理警报"""
        # 处理队列中的新警报
        while not self.alert_queue.empty():
            try:
                alert = self.alert_queue.get_nowait()
                
                # 尝试自动修复
                if not alert.auto_fix_attempted:
                    self._attempt_auto_fix(alert)
                    alert.auto_fix_attempted = True
                
                # 调用回调函数
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"警报回调函数异常: {e}")
                        
            except queue.Empty:
                break
            except Exception as e:
                self.logger.error(f"处理警报异常: {e}")
    
    def _attempt_auto_fix(self, alert: HealthAlert):
        """尝试自动修复"""
        try:
            if alert.metric_name == 'memory_usage':
                self._fix_memory_usage()
            elif alert.metric_name == 'cpu_usage':
                self._fix_cpu_usage()
            elif alert.metric_name == 'disk_usage':
                self._fix_disk_usage()
            elif alert.metric_name == 'thread_count':
                self._fix_thread_count()
            elif alert.metric_name == 'file_handles':
                self._fix_file_handles()
                
        except Exception as e:
            self.logger.error(f"自动修复失败: {e}")
    
    def _fix_memory_usage(self):
        """修复内存使用问题"""
        self.logger.info("尝试修复内存使用问题")
        
        # 强制垃圾回收
        gc.collect()
        
        # 清理缓存（如果有的话）
        try:
            # 这里可以添加应用特定的缓存清理逻辑
            pass
        except Exception as e:
            self.logger.error(f"清理缓存失败: {e}")
    
    def _fix_cpu_usage(self):
        """修复CPU使用问题"""
        self.logger.info("尝试修复CPU使用问题")
        
        # 降低线程优先级
        try:
            if hasattr(os, 'nice'):
                os.nice(1)  # Unix系统
        except Exception:
            pass
    
    def _fix_disk_usage(self):
        """修复磁盘使用问题"""
        self.logger.info("尝试修复磁盘使用问题")
        
        # 清理临时文件
        try:
            temp_dirs = ['logs', 'data/temp', 'backups']
            for temp_dir in temp_dirs:
                temp_path = Path(temp_dir)
                if temp_path.exists():
                    # 清理旧文件（超过7天）
                    cutoff_time = time.time() - (7 * 24 * 3600)
                    for file_path in temp_path.rglob('*'):
                        if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                            try:
                                file_path.unlink()
                                self.logger.debug(f"已删除旧文件: {file_path}")
                            except Exception as e:
                                self.logger.error(f"删除文件失败 {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"清理临时文件失败: {e}")
    
    def _fix_thread_count(self):
        """修复线程数量问题"""
        self.logger.info("尝试修复线程数量问题")
        
        # 记录线程信息用于调试
        try:
            thread_count = threading.active_count()
            self.logger.warning(f"当前活动线程数: {thread_count}")
            
            # 列出所有线程
            for thread in threading.enumerate():
                self.logger.debug(f"线程: {thread.name}, 守护进程: {thread.daemon}")
                
        except Exception as e:
            self.logger.error(f"获取线程信息失败: {e}")
    
    def _fix_file_handles(self):
        """修复文件句柄问题"""
        self.logger.info("尝试修复文件句柄问题")
        
        # 这里可以添加关闭未使用文件句柄的逻辑
        try:
            # 强制垃圾回收可能会关闭一些未引用的文件
            gc.collect()
        except Exception as e:
            self.logger.error(f"修复文件句柄失败: {e}")
    
    def add_alert_callback(self, callback: Callable[[HealthAlert], None]):
        """添加警报回调函数"""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[HealthAlert], None]):
        """移除警报回调函数"""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    def get_overall_health(self) -> HealthStatus:
        """获取整体健康状态"""
        if not self.metrics:
            return HealthStatus.UNKNOWN
        
        critical_count = 0
        warning_count = 0
        
        for metric in self.metrics.values():
            if metric.value >= metric.threshold_critical:
                critical_count += 1
            elif metric.value >= metric.threshold_warning:
                warning_count += 1
        
        if critical_count > 0:
            return HealthStatus.CRITICAL
        elif warning_count > 2:
            return HealthStatus.WARNING
        elif warning_count > 0:
            return HealthStatus.GOOD
        else:
            return HealthStatus.EXCELLENT
    
    def get_health_report(self) -> Dict[str, Any]:
        """获取健康报告"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        report = {
            'overall_status': self.get_overall_health().value,
            'uptime_seconds': uptime,
            'uptime_formatted': self._format_uptime(uptime),
            'metrics': {},
            'active_alerts': [],
            'resolved_alerts': [],
            'timestamp': current_time
        }
        
        # 添加指标信息
        for name, metric in self.metrics.items():
            status = HealthStatus.EXCELLENT
            if metric.value >= metric.threshold_critical:
                status = HealthStatus.CRITICAL
            elif metric.value >= metric.threshold_warning:
                status = HealthStatus.WARNING
            
            report['metrics'][name] = {
                'name': metric.name,
                'value': metric.value,
                'unit': metric.unit,
                'status': status.value,
                'threshold_warning': metric.threshold_warning,
                'threshold_critical': metric.threshold_critical,
                'last_updated': metric.last_updated
            }
        
        # 添加警报信息
        for alert in self.alerts:
            alert_info = {
                'metric_name': alert.metric_name,
                'severity': alert.severity.value,
                'message': alert.message,
                'timestamp': alert.timestamp,
                'auto_fix_attempted': alert.auto_fix_attempted
            }
            
            if alert.resolved:
                report['resolved_alerts'].append(alert_info)
            else:
                report['active_alerts'].append(alert_info)
        
        return report
    
    def _format_uptime(self, uptime_seconds: float) -> str:
        """格式化运行时间"""
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        
        if days > 0:
            return f"{days}天 {hours}小时 {minutes}分钟"
        elif hours > 0:
            return f"{hours}小时 {minutes}分钟"
        else:
            return f"{minutes}分钟 {seconds}秒"
    
    def resolve_alert(self, metric_name: str):
        """解决警报"""
        for alert in self.alerts:
            if alert.metric_name == metric_name and not alert.resolved:
                alert.resolved = True
                self.logger.info(f"警报已解决: {alert.message}")
    
    def clear_resolved_alerts(self):
        """清理已解决的警报"""
        resolved_count = len([alert for alert in self.alerts if alert.resolved])
        self.alerts = [alert for alert in self.alerts if not alert.resolved]
        if resolved_count > 0:
            self.logger.info(f"已清理 {resolved_count} 个已解决的警报")
    
    def set_metric_thresholds(self, metric_name: str, warning: float, critical: float):
        """设置指标阈值"""
        if metric_name in self.metrics:
            self.metrics[metric_name].threshold_warning = warning
            self.metrics[metric_name].threshold_critical = critical
            self.logger.info(f"已更新 {metric_name} 的阈值: 警告={warning}, 严重={critical}")

# 全局健康监控实例
_global_health_monitor: Optional[SystemHealthMonitor] = None

def get_health_monitor() -> SystemHealthMonitor:
    """获取全局健康监控实例"""
    global _global_health_monitor
    if _global_health_monitor is None:
        _global_health_monitor = SystemHealthMonitor()
    return _global_health_monitor

def start_health_monitoring():
    """启动健康监控"""
    monitor = get_health_monitor()
    monitor.start_monitoring()

def stop_health_monitoring():
    """停止健康监控"""
    monitor = get_health_monitor()
    monitor.stop_monitoring()

def get_current_health_status() -> HealthStatus:
    """获取当前健康状态"""
    monitor = get_health_monitor()
    return monitor.get_overall_health()

__all__ = ['SystemHealthMonitor', 'HealthStatus', 'HealthMetric', 'HealthAlert',
           'get_health_monitor', 'start_health_monitoring', 'stop_health_monitoring',
           'get_current_health_status']