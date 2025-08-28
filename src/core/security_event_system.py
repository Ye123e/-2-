#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全事件系统 - 事件收集、分析、响应、日志记录
"""

import json
import sqlite3
import threading
import time
import queue
from typing import List, Dict, Optional, Any, Callable, Set
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid

from ..utils.logger import LoggerMixin
from .real_time_protection import SecurityEvent, EventType, ActionType, ThreatLevel


class EventPriority(Enum):
    """事件优先级"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class EventStatus(Enum):
    """事件状态"""
    NEW = "NEW"                    # 新事件
    PROCESSING = "PROCESSING"      # 处理中
    HANDLED = "HANDLED"           # 已处理
    IGNORED = "IGNORED"           # 已忽略
    ESCALATED = "ESCALATED"       # 已升级


class AnalysisType(Enum):
    """分析类型"""
    CORRELATION = "CORRELATION"    # 关联分析
    TREND = "TREND"               # 趋势分析
    ANOMALY = "ANOMALY"          # 异常检测
    PATTERN = "PATTERN"          # 模式识别


@dataclass
class EventCorrelation:
    """事件关联"""
    correlation_id: str
    related_events: List[str]
    correlation_type: str
    confidence: float
    description: str
    created_time: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatPattern:
    """威胁模式"""
    pattern_id: str
    name: str
    description: str
    event_sequence: List[EventType]
    time_window_minutes: int
    threat_score: float
    indicators: List[str]


@dataclass
class SecurityIncident:
    """安全事件"""
    incident_id: str
    title: str
    description: str
    severity: EventPriority
    status: EventStatus
    related_events: List[str]
    created_time: datetime
    updated_time: datetime
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    tags: List[str] = field(default_factory=list)


class EventCollector(LoggerMixin):
    """事件收集器"""
    
    def __init__(self, event_manager):
        self.event_manager = event_manager
        self.event_queue = queue.Queue(maxsize=10000)
        self.collector_thread = None
        self.running = False
        
        # 事件过滤器
        self.filters: List[Callable[[SecurityEvent], bool]] = []
        
        # 事件增强器
        self.enrichers: List[Callable[[SecurityEvent], SecurityEvent]] = []
    
    def start(self):
        """启动事件收集"""
        if self.running:
            return
        
        self.running = True
        self.collector_thread = threading.Thread(target=self._process_events, daemon=True)
        self.collector_thread.start()
        self.logger.info("事件收集器已启动")
    
    def stop(self):
        """停止事件收集"""
        self.running = False
        if self.collector_thread:
            self.collector_thread.join(timeout=5)
        self.logger.info("事件收集器已停止")
    
    def collect_event(self, event: SecurityEvent):
        """收集事件"""
        try:
            # 应用过滤器
            for filter_func in self.filters:
                if not filter_func(event):
                    return
            
            # 应用增强器
            for enricher in self.enrichers:
                event = enricher(event)
            
            # 添加到队列
            if not self.event_queue.full():
                self.event_queue.put(event)
            else:
                self.logger.warning("事件队列已满，丢弃事件")
                
        except Exception as e:
            self.logger.error(f"收集事件失败: {e}")
    
    def _process_events(self):
        """处理事件主循环"""
        while self.running:
            try:
                # 从队列获取事件
                event = self.event_queue.get(timeout=1)
                
                # 提交给事件管理器
                self.event_manager.process_event(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"处理事件异常: {e}")
    
    def add_filter(self, filter_func: Callable[[SecurityEvent], bool]):
        """添加事件过滤器"""
        self.filters.append(filter_func)
    
    def add_enricher(self, enricher: Callable[[SecurityEvent], SecurityEvent]):
        """添加事件增强器"""
        self.enrichers.append(enricher)


class EventAnalyzer(LoggerMixin):
    """事件分析器"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.correlations: Dict[str, EventCorrelation] = {}
        self.threat_patterns: List[ThreatPattern] = []
        
        self._init_threat_patterns()
    
    def _init_threat_patterns(self):
        """初始化威胁模式"""
        patterns = [
            ThreatPattern(
                pattern_id="multi_stage_attack",
                name="多阶段攻击",
                description="连续的文件创建、进程启动和网络连接",
                event_sequence=[EventType.FILE_CREATED, EventType.PROCESS_STARTED, EventType.NETWORK_CONNECTION],
                time_window_minutes=10,
                threat_score=0.85,
                indicators=["恶意文件投放", "后门进程", "C&C通信"]
            ),
            ThreatPattern(
                pattern_id="data_exfiltration",
                name="数据窃取",
                description="大量文件访问后的网络传输",
                event_sequence=[EventType.FILE_MODIFIED, EventType.NETWORK_CONNECTION],
                time_window_minutes=5,
                threat_score=0.75,
                indicators=["文件访问异常", "数据传输"]
            )
        ]
        
        self.threat_patterns.extend(patterns)
    
    def analyze_correlation(self, events: List[SecurityEvent]) -> List[EventCorrelation]:
        """分析事件关联"""
        correlations = []
        
        try:
            # 按时间排序
            events.sort(key=lambda e: e.timestamp)
            
            # 检查威胁模式
            for pattern in self.threat_patterns:
                pattern_correlations = self._detect_pattern(events, pattern)
                correlations.extend(pattern_correlations)
            
            # 检查同源事件关联
            source_correlations = self._analyze_source_correlation(events)
            correlations.extend(source_correlations)
            
        except Exception as e:
            self.logger.error(f"分析事件关联失败: {e}")
        
        return correlations
    
    def _detect_pattern(self, events: List[SecurityEvent], pattern: ThreatPattern) -> List[EventCorrelation]:
        """检测威胁模式"""
        correlations = []
        
        try:
            # 时间窗口
            time_window = timedelta(minutes=pattern.time_window_minutes)
            
            for i, start_event in enumerate(events):
                if start_event.event_type != pattern.event_sequence[0]:
                    continue
                
                # 查找模式序列
                matched_events = [start_event.event_id]
                pattern_index = 1
                
                for j in range(i + 1, len(events)):
                    current_event = events[j]
                    
                    # 检查时间窗口
                    if current_event.timestamp - start_event.timestamp > time_window:
                        break
                    
                    # 检查事件类型匹配
                    if (pattern_index < len(pattern.event_sequence) and 
                        current_event.event_type == pattern.event_sequence[pattern_index]):
                        matched_events.append(current_event.event_id)
                        pattern_index += 1
                        
                        # 完整模式匹配
                        if pattern_index == len(pattern.event_sequence):
                            correlation = EventCorrelation(
                                correlation_id=str(uuid.uuid4()),
                                related_events=matched_events,
                                correlation_type=f"PATTERN_{pattern.pattern_id}",
                                confidence=pattern.threat_score,
                                description=f"检测到威胁模式: {pattern.name}"
                            )
                            correlations.append(correlation)
                            break
            
        except Exception as e:
            self.logger.error(f"检测威胁模式失败: {e}")
        
        return correlations
    
    def _analyze_source_correlation(self, events: List[SecurityEvent]) -> List[EventCorrelation]:
        """分析同源事件关联"""
        correlations = []
        
        try:
            # 按源分组
            source_groups: Dict[str, List[SecurityEvent]] = {}
            
            for event in events:
                source = event.source
                if source not in source_groups:
                    source_groups[source] = []
                source_groups[source].append(event)
            
            # 分析每个源的事件
            for source, source_events in source_groups.items():
                if len(source_events) >= 3:  # 至少3个事件才考虑关联
                    correlation = EventCorrelation(
                        correlation_id=str(uuid.uuid4()),
                        related_events=[e.event_id for e in source_events],
                        correlation_type="SOURCE_CORRELATION",
                        confidence=0.6,
                        description=f"同源多事件: {source} ({len(source_events)}个事件)"
                    )
                    correlations.append(correlation)
            
        except Exception as e:
            self.logger.error(f"分析同源关联失败: {e}")
        
        return correlations
    
    def analyze_trends(self, events: List[SecurityEvent], time_period: timedelta) -> Dict[str, Any]:
        """分析事件趋势"""
        trends = {
            'event_count_trend': {},
            'threat_level_trend': {},
            'event_type_distribution': {},
            'hourly_distribution': {}
        }
        
        try:
            current_time = datetime.now()
            start_time = current_time - time_period
            
            # 过滤时间范围内的事件
            filtered_events = [e for e in events if e.timestamp >= start_time]
            
            # 按小时统计事件数量
            for event in filtered_events:
                hour = event.timestamp.hour
                if hour not in trends['hourly_distribution']:
                    trends['hourly_distribution'][hour] = 0
                trends['hourly_distribution'][hour] += 1
                
                # 统计事件类型分布
                event_type = event.event_type.value
                if event_type not in trends['event_type_distribution']:
                    trends['event_type_distribution'][event_type] = 0
                trends['event_type_distribution'][event_type] += 1
                
                # 统计威胁级别分布
                threat_level = event.threat_level.value
                if threat_level not in trends['threat_level_trend']:
                    trends['threat_level_trend'][threat_level] = 0
                trends['threat_level_trend'][threat_level] += 1
            
        except Exception as e:
            self.logger.error(f"分析事件趋势失败: {e}")
        
        return trends
    
    def detect_anomalies(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """检测异常事件"""
        anomalies = []
        
        try:
            # 计算基线统计
            baseline_stats = self._calculate_baseline_stats(events)
            
            # 检测事件频率异常
            freq_anomalies = self._detect_frequency_anomalies(events, baseline_stats)
            anomalies.extend(freq_anomalies)
            
            # 检测威胁级别异常
            threat_anomalies = self._detect_threat_level_anomalies(events, baseline_stats)
            anomalies.extend(threat_anomalies)
            
        except Exception as e:
            self.logger.error(f"检测异常失败: {e}")
        
        return anomalies
    
    def _calculate_baseline_stats(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """计算基线统计"""
        stats = {
            'avg_events_per_hour': 0,
            'avg_threat_score': 0,
            'common_event_types': [],
            'time_range': timedelta(hours=24)
        }
        
        if not events:
            return stats
        
        # 计算平均每小时事件数
        if len(events) > 0:
            time_span = (max(e.timestamp for e in events) - min(e.timestamp for e in events)).total_seconds() / 3600
            if time_span > 0:
                stats['avg_events_per_hour'] = len(events) / time_span
        
        return stats
    
    def _detect_frequency_anomalies(self, events: List[SecurityEvent], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测频率异常"""
        anomalies = []
        
        # 简化的异常检测：如果某小时的事件数超过平均值的3倍
        threshold = baseline.get('avg_events_per_hour', 0) * 3
        
        if threshold > 0:
            hourly_counts = {}
            for event in events:
                hour_key = event.timestamp.strftime('%Y-%m-%d %H')
                if hour_key not in hourly_counts:
                    hourly_counts[hour_key] = 0
                hourly_counts[hour_key] += 1
            
            for hour, count in hourly_counts.items():
                if count > threshold:
                    anomalies.append({
                        'type': 'FREQUENCY_ANOMALY',
                        'description': f'事件频率异常: {hour} ({count}个事件)',
                        'severity': 'HIGH' if count > threshold * 2 else 'MEDIUM',
                        'timestamp': hour,
                        'count': count,
                        'threshold': threshold
                    })
        
        return anomalies
    
    def _detect_threat_level_anomalies(self, events: List[SecurityEvent], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测威胁级别异常"""
        anomalies = []
        
        # 检测高威胁事件集中出现
        high_threat_events = [e for e in events if e.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
        
        if len(high_threat_events) >= 5:  # 5个以上高威胁事件
            time_window = timedelta(minutes=30)
            
            for i, event in enumerate(high_threat_events):
                cluster_events = [e for e in high_threat_events[i:] 
                                if e.timestamp - event.timestamp <= time_window]
                
                if len(cluster_events) >= 3:
                    anomalies.append({
                        'type': 'THREAT_CLUSTER',
                        'description': f'高威胁事件集群: {len(cluster_events)}个事件在30分钟内',
                        'severity': 'CRITICAL',
                        'timestamp': event.timestamp.isoformat(),
                        'event_count': len(cluster_events),
                        'time_window': '30 minutes'
                    })
                    break
        
        return anomalies


class SecurityEventManager(LoggerMixin):
    """安全事件管理器"""
    
    def __init__(self, db_path: str = "data/security_events.db"):
        self.db_path = db_path
        self.collector = EventCollector(self)
        self.analyzer = EventAnalyzer(db_path)
        
        # 事件存储
        self.events: Dict[str, SecurityEvent] = {}
        self.incidents: Dict[str, SecurityIncident] = {}
        
        # 事件处理器
        self.event_handlers: List[Callable[[SecurityEvent], None]] = []
        self.incident_handlers: List[Callable[[SecurityIncident], None]] = []
        
        # 统计信息
        self.stats = {
            'total_events': 0,
            'events_by_type': {},
            'events_by_threat_level': {},
            'incidents_created': 0,
            'correlations_found': 0
        }
        
        self._init_database()
    
    def _init_database(self):
        """初始化数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 事件表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        details TEXT,
                        threat_level TEXT NOT NULL,
                        action_taken TEXT,
                        description TEXT,
                        processed BOOLEAN DEFAULT 0
                    )
                ''')
                
                # 事件表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        related_events TEXT,
                        created_time TEXT NOT NULL,
                        updated_time TEXT NOT NULL,
                        assigned_to TEXT,
                        resolution TEXT,
                        tags TEXT
                    )
                ''')
                
                # 关联表
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS event_correlations (
                        correlation_id TEXT PRIMARY KEY,
                        related_events TEXT NOT NULL,
                        correlation_type TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        description TEXT,
                        created_time TEXT NOT NULL
                    )
                ''')
                
                # 创建索引
                conn.execute('CREATE INDEX IF NOT EXISTS idx_event_timestamp ON security_events(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON security_events(threat_level)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_incident_status ON security_incidents(status)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化事件数据库失败: {e}")
    
    def start(self):
        """启动事件管理器"""
        self.collector.start()
        self.logger.info("安全事件管理器已启动")
    
    def stop(self):
        """停止事件管理器"""
        self.collector.stop()
        self.logger.info("安全事件管理器已停止")
    
    def submit_event(self, event: SecurityEvent):
        """提交事件"""
        self.collector.collect_event(event)
    
    def process_event(self, event: SecurityEvent):
        """处理事件"""
        try:
            # 存储事件
            self._store_event(event)
            
            # 更新统计
            self._update_event_stats(event)
            
            # 通知处理器
            for handler in self.event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error(f"事件处理器异常: {e}")
            
            # 检查是否需要创建事件
            self._check_incident_creation(event)
            
        except Exception as e:
            self.logger.error(f"处理事件失败: {e}")
    
    def _store_event(self, event: SecurityEvent):
        """存储事件到数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO security_events
                    (event_id, event_type, timestamp, device_id, source, details,
                     threat_level, action_taken, description, processed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.event_type.value,
                    event.timestamp.isoformat(),
                    event.device_id,
                    event.source,
                    json.dumps(event.details),
                    event.threat_level.value,
                    event.action_taken.value if event.action_taken else None,
                    event.description,
                    False
                ))
                conn.commit()
            
            self.events[event.event_id] = event
            
        except Exception as e:
            self.logger.error(f"存储事件失败: {e}")
    
    def _update_event_stats(self, event: SecurityEvent):
        """更新事件统计"""
        self.stats['total_events'] += 1
        
        # 按类型统计
        event_type = event.event_type.value
        if event_type not in self.stats['events_by_type']:
            self.stats['events_by_type'][event_type] = 0
        self.stats['events_by_type'][event_type] += 1
        
        # 按威胁级别统计
        threat_level = event.threat_level.value
        if threat_level not in self.stats['events_by_threat_level']:
            self.stats['events_by_threat_level'][threat_level] = 0
        self.stats['events_by_threat_level'][threat_level] += 1
    
    def _check_incident_creation(self, event: SecurityEvent):
        """检查是否需要创建事件"""
        # 高威胁级别事件自动创建事件
        if event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self._create_incident_for_event(event)
    
    def _create_incident_for_event(self, event: SecurityEvent):
        """为事件创建事件"""
        try:
            incident = SecurityIncident(
                incident_id=str(uuid.uuid4()),
                title=f"高威胁事件: {event.event_type.value}",
                description=event.description or f"检测到{event.threat_level.value}级别威胁",
                severity=EventPriority.HIGH if event.threat_level == ThreatLevel.HIGH else EventPriority.CRITICAL,
                status=EventStatus.NEW,
                related_events=[event.event_id],
                created_time=datetime.now(),
                updated_time=datetime.now(),
                tags=[event.event_type.value, event.threat_level.value]
            )
            
            self._store_incident(incident)
            
            # 通知事件处理器
            for handler in self.incident_handlers:
                try:
                    handler(incident)
                except Exception as e:
                    self.logger.error(f"事件处理器异常: {e}")
            
        except Exception as e:
            self.logger.error(f"创建事件失败: {e}")
    
    def _store_incident(self, incident: SecurityIncident):
        """存储事件"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO security_incidents
                    (incident_id, title, description, severity, status, related_events,
                     created_time, updated_time, assigned_to, resolution, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident.incident_id,
                    incident.title,
                    incident.description,
                    incident.severity.value,
                    incident.status.value,
                    json.dumps(incident.related_events),
                    incident.created_time.isoformat(),
                    incident.updated_time.isoformat(),
                    incident.assigned_to,
                    incident.resolution,
                    json.dumps(incident.tags)
                ))
                conn.commit()
            
            self.incidents[incident.incident_id] = incident
            self.stats['incidents_created'] += 1
            
        except Exception as e:
            self.logger.error(f"存储事件失败: {e}")
    
    def analyze_events(self, time_period: timedelta = timedelta(hours=24)) -> Dict[str, Any]:
        """分析事件"""
        try:
            # 获取时间范围内的事件
            current_time = datetime.now()
            start_time = current_time - time_period
            
            recent_events = [e for e in self.events.values() if e.timestamp >= start_time]
            
            analysis_result = {
                'correlations': [],
                'trends': {},
                'anomalies': [],
                'summary': {
                    'total_events': len(recent_events),
                    'high_threat_events': len([e for e in recent_events if e.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]),
                    'analysis_period': time_period.total_seconds() / 3600
                }
            }
            
            if recent_events:
                # 关联分析
                correlations = self.analyzer.analyze_correlation(recent_events)
                analysis_result['correlations'] = [asdict(c) for c in correlations]
                self.stats['correlations_found'] += len(correlations)
                
                # 趋势分析
                analysis_result['trends'] = self.analyzer.analyze_trends(recent_events, time_period)
                
                # 异常检测
                analysis_result['anomalies'] = self.analyzer.detect_anomalies(recent_events)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"分析事件失败: {e}")
            return {}
    
    def add_event_handler(self, handler: Callable[[SecurityEvent], None]):
        """添加事件处理器"""
        self.event_handlers.append(handler)
    
    def add_incident_handler(self, handler: Callable[[SecurityIncident], None]):
        """添加事件处理器"""
        self.incident_handlers.append(handler)
    
    def get_events(self, limit: int = 100, event_type: Optional[EventType] = None, 
                   threat_level: Optional[ThreatLevel] = None) -> List[SecurityEvent]:
        """获取事件列表"""
        events = list(self.events.values())
        
        # 过滤条件
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if threat_level:
            events = [e for e in events if e.threat_level == threat_level]
        
        # 按时间排序，返回最新的
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
    
    def get_incidents(self, status: Optional[EventStatus] = None) -> List[SecurityIncident]:
        """获取事件列表"""
        incidents = list(self.incidents.values())
        
        if status:
            incidents = [i for i in incidents if i.status == status]
        
        incidents.sort(key=lambda i: i.created_time, reverse=True)
        return incidents
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.stats.copy()