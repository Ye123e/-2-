#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实时监控引擎
提供持续的安全状态监控和威胁检测
"""

import time
import threading
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque

from ..models import DeviceInfo, SecurityEvent, ThreatLevel, MonitoringStatus
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager


class SecurityEvent:
    """安全事件"""
    
    def __init__(self, 
                 event_type: str,
                 device_id: str,
                 severity: str,
                 description: str,
                 details: Dict[str, Any] = None):
        self.event_id = f"{device_id}_{int(time.time())}"
        self.event_type = event_type
        self.device_id = device_id
        self.severity = severity
        self.description = description
        self.details = details or {}
        self.timestamp = datetime.now()
        self.acknowledged = False


class DeviceMonitor(LoggerMixin):
    """设备监控器"""
    
    def __init__(self, device_id: str, device_manager: DeviceManager):
        self.device_id = device_id
        self.device_manager = device_manager
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # 监控配置
        self.check_interval = 30  # 30秒检查间隔
        self.alert_thresholds = {
            'cpu_usage': 80,
            'memory_usage': 85,
            'new_app_installations': 3,
            'suspicious_permissions': 2
        }
        
        # 状态缓存
        self.last_app_list: Set[str] = set()
        self.last_process_list: Set[str] = set()
        self.performance_history = deque(maxlen=100)
        
        # 事件回调
        self.event_callbacks: List[Callable[[SecurityEvent], None]] = []
    
    def add_event_callback(self, callback: Callable[[SecurityEvent], None]):
        """添加事件回调"""
        self.event_callbacks.append(callback)
    
    def _notify_event(self, event: SecurityEvent):
        """通知安全事件"""
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"事件回调执行失败: {e}")
    
    def start_monitoring(self):
        """启动监控"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info(f"开始监控设备: {self.device_id}")
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info(f"停止监控设备: {self.device_id}")
    
    def _monitoring_loop(self):
        """监控主循环"""
        while self.monitoring_active:
            try:
                self._check_device_status()
                self._check_new_applications()
                self._check_system_performance()
                self._check_network_activity()
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"监控检查失败: {e}")
                time.sleep(self.check_interval)
    
    def _check_device_status(self):
        """检查设备状态"""
        try:
            # 检查设备连接状态
            device_info = self.device_manager.get_device(self.device_id)
            if not device_info or device_info.status != "online":
                event = SecurityEvent(
                    event_type="device_disconnected",
                    device_id=self.device_id,
                    severity="MEDIUM",
                    description="设备连接丢失",
                    details={"last_seen": datetime.now()}
                )
                self._notify_event(event)
        
        except Exception as e:
            self.logger.error(f"设备状态检查失败: {e}")
    
    def _check_new_applications(self):
        """检查新安装的应用"""
        try:
            # 获取当前应用列表
            result = self.device_manager.execute_command(
                self.device_id, "pm list packages"
            )
            
            if not result:
                return
            
            current_apps = set()
            for line in result.split('\n'):
                if line.startswith('package:'):
                    package_name = line.replace('package:', '').strip()
                    current_apps.add(package_name)
            
            # 检查新安装的应用
            if self.last_app_list:
                new_apps = current_apps - self.last_app_list
                if len(new_apps) > self.alert_thresholds['new_app_installations']:
                    event = SecurityEvent(
                        event_type="bulk_app_installation",
                        device_id=self.device_id,
                        severity="HIGH",
                        description=f"检测到批量应用安装: {len(new_apps)} 个新应用",
                        details={"new_apps": list(new_apps)}
                    )
                    self._notify_event(event)
                
                # 检查可疑应用
                for app in new_apps:
                    if self._is_suspicious_app(app):
                        event = SecurityEvent(
                            event_type="suspicious_app_installed",
                            device_id=self.device_id,
                            severity="HIGH",
                            description=f"检测到可疑应用安装: {app}",
                            details={"package_name": app}
                        )
                        self._notify_event(event)
            
            self.last_app_list = current_apps
        
        except Exception as e:
            self.logger.error(f"应用检查失败: {e}")
    
    def _check_system_performance(self):
        """检查系统性能"""
        try:
            # CPU使用率
            cpu_result = self.device_manager.execute_command(
                self.device_id, "dumpsys cpuinfo | head -1"
            )
            
            # 内存使用情况  
            mem_result = self.device_manager.execute_command(
                self.device_id, "dumpsys meminfo | grep 'Total RAM'"
            )
            
            performance_data = {
                'timestamp': datetime.now(),
                'cpu_info': cpu_result.strip() if cpu_result else "",
                'memory_info': mem_result.strip() if mem_result else ""
            }
            
            self.performance_history.append(performance_data)
            
            # 检查性能异常
            if len(self.performance_history) >= 5:
                self._analyze_performance_trends()
        
        except Exception as e:
            self.logger.error(f"性能检查失败: {e}")
    
    def _check_network_activity(self):
        """检查网络活动"""
        try:
            # 检查网络连接
            netstat_result = self.device_manager.execute_command(
                self.device_id, "netstat -an | head -20"
            )
            
            if netstat_result:
                # 分析可疑网络连接
                suspicious_connections = self._analyze_network_connections(netstat_result)
                
                if suspicious_connections:
                    event = SecurityEvent(
                        event_type="suspicious_network_activity",
                        device_id=self.device_id,
                        severity="MEDIUM",
                        description="检测到可疑网络连接",
                        details={"connections": suspicious_connections}
                    )
                    self._notify_event(event)
        
        except Exception as e:
            self.logger.error(f"网络检查失败: {e}")
    
    def _is_suspicious_app(self, package_name: str) -> bool:
        """检查应用是否可疑"""
        suspicious_patterns = [
            'fake', 'trojan', 'malware', 'virus', 'spy'
        ]
        
        return any(pattern in package_name.lower() for pattern in suspicious_patterns)
    
    def _analyze_performance_trends(self):
        """分析性能趋势"""
        # 简化的性能分析
        recent_data = list(self.performance_history)[-5:]
        
        # 检查是否有异常的CPU或内存使用
        # 这里可以添加更复杂的趋势分析算法
        pass
    
    def _analyze_network_connections(self, netstat_output: str) -> List[str]:
        """分析网络连接"""
        suspicious = []
        
        # 检查可疑端口和地址
        suspicious_ports = ['1234', '4444', '5555', '6666']
        
        for line in netstat_output.split('\n'):
            if any(port in line for port in suspicious_ports):
                suspicious.append(line.strip())
        
        return suspicious


class RealTimeMonitoringEngine(LoggerMixin):
    """实时监控引擎"""
    
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
        self.device_monitors: Dict[str, DeviceMonitor] = {}
        self.security_events: deque = deque(maxlen=1000)
        self.event_callbacks: List[Callable[[SecurityEvent], None]] = []
        
        # 监控状态
        self.monitoring_enabled = False
        self.global_alert_level = ThreatLevel.LOW
        
        # 统计信息
        self.monitoring_stats = {
            'total_events': 0,
            'critical_events': 0,
            'high_events': 0,
            'medium_events': 0,
            'low_events': 0,
            'start_time': None
        }
    
    def add_event_callback(self, callback: Callable[[SecurityEvent], None]):
        """添加全局事件回调"""
        self.event_callbacks.append(callback)
    
    def start_monitoring(self, device_ids: List[str] = None):
        """启动全局监控"""
        if device_ids is None:
            device_ids = [d.device_id for d in self.device_manager.get_devices()]
        
        self.monitoring_enabled = True
        self.monitoring_stats['start_time'] = datetime.now()
        
        for device_id in device_ids:
            if device_id not in self.device_monitors:
                monitor = DeviceMonitor(device_id, self.device_manager)
                monitor.add_event_callback(self._handle_security_event)
                self.device_monitors[device_id] = monitor
            
            self.device_monitors[device_id].start_monitoring()
        
        self.logger.info(f"启动实时监控，监控 {len(device_ids)} 台设备")
    
    def stop_monitoring(self):
        """停止全局监控"""
        self.monitoring_enabled = False
        
        for monitor in self.device_monitors.values():
            monitor.stop_monitoring()
        
        self.logger.info("停止实时监控")
    
    def add_device_monitoring(self, device_id: str):
        """添加设备监控"""
        if device_id not in self.device_monitors:
            monitor = DeviceMonitor(device_id, self.device_manager)
            monitor.add_event_callback(self._handle_security_event)
            self.device_monitors[device_id] = monitor
            
            if self.monitoring_enabled:
                monitor.start_monitoring()
                
        self.logger.info(f"添加设备监控: {device_id}")
    
    def remove_device_monitoring(self, device_id: str):
        """移除设备监控"""
        if device_id in self.device_monitors:
            self.device_monitors[device_id].stop_monitoring()
            del self.device_monitors[device_id]
            self.logger.info(f"移除设备监控: {device_id}")
    
    def _handle_security_event(self, event: SecurityEvent):
        """处理安全事件"""
        # 记录事件
        self.security_events.append(event)
        self.monitoring_stats['total_events'] += 1
        
        # 更新统计
        if event.severity == "CRITICAL":
            self.monitoring_stats['critical_events'] += 1
        elif event.severity == "HIGH":
            self.monitoring_stats['high_events'] += 1
        elif event.severity == "MEDIUM":
            self.monitoring_stats['medium_events'] += 1
        else:
            self.monitoring_stats['low_events'] += 1
        
        # 更新全局告警级别
        self._update_global_alert_level()
        
        # 通知回调
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"事件回调执行失败: {e}")
        
        self.logger.warning(f"安全事件: {event.event_type} - {event.description}")
    
    def _update_global_alert_level(self):
        """更新全局告警级别"""
        recent_events = [e for e in self.security_events 
                        if (datetime.now() - e.timestamp).seconds < 3600]  # 最近1小时
        
        if any(e.severity == "CRITICAL" for e in recent_events):
            self.global_alert_level = ThreatLevel.CRITICAL
        elif any(e.severity == "HIGH" for e in recent_events):
            self.global_alert_level = ThreatLevel.HIGH
        elif any(e.severity == "MEDIUM" for e in recent_events):
            self.global_alert_level = ThreatLevel.MEDIUM
        else:
            self.global_alert_level = ThreatLevel.LOW
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """获取监控状态"""
        return {
            'enabled': self.monitoring_enabled,
            'monitored_devices': len(self.device_monitors),
            'global_alert_level': self.global_alert_level,
            'recent_events': len([e for e in self.security_events 
                                if (datetime.now() - e.timestamp).seconds < 300]),
            'stats': self.monitoring_stats
        }
    
    def get_recent_events(self, limit: int = 50) -> List[SecurityEvent]:
        """获取最近的安全事件"""
        recent_events = sorted(self.security_events, 
                             key=lambda x: x.timestamp, reverse=True)
        return recent_events[:limit]
    
    def acknowledge_event(self, event_id: str) -> bool:
        """确认处理安全事件"""
        for event in self.security_events:
            if event.event_id == event_id:
                event.acknowledged = True
                return True
        return False