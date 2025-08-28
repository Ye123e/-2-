#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据模型定义
包含设备信息、诊断报告等数据结构
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

class ConnectionType(Enum):
    """连接类型枚举"""
    USB = "USB"
    WIFI = "WIFI"
    UNKNOWN = "UNKNOWN"

class IssueCategory(Enum):
    """问题类别枚举"""
    STORAGE = "STORAGE"
    SYSTEM_FILES = "SYSTEM_FILES"
    RESOURCES = "RESOURCES"
    VIRUS = "VIRUS"
    ERROR_FILES = "ERROR_FILES"
    APPS = "APPS"
    PERMISSIONS = "PERMISSIONS"
    NETWORK = "NETWORK"
    BOOT = "BOOT"

class IssueSeverity(Enum):
    """问题严重程度枚举"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class DeviceInfo:
    """设备信息数据模型"""
    device_id: str
    model: str = ""
    android_version: str = ""
    build_number: str = ""
    root_status: bool = False
    storage_total: int = 0
    storage_free: int = 0
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    last_connected: Optional[datetime] = None
    manufacturer: str = ""
    cpu_arch: str = ""
    screen_resolution: str = ""
    
    def __post_init__(self):
        if self.last_connected is None:
            self.last_connected = datetime.now()
    
    @property
    def storage_used(self) -> int:
        """计算已使用存储空间"""
        return self.storage_total - self.storage_free
    
    @property
    def storage_usage_percent(self) -> float:
        """计算存储空间使用百分比"""
        if self.storage_total == 0:
            return 0.0
        return (self.storage_used / self.storage_total) * 100

@dataclass
class Issue:
    """问题信息数据模型"""
    category: IssueCategory
    severity: IssueSeverity
    description: str
    auto_fixable: bool = False
    fix_method: str = ""
    affected_files: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'category': self.category.value,
            'severity': self.severity.value,
            'description': self.description,
            'auto_fixable': self.auto_fixable,
            'fix_method': self.fix_method,
            'affected_files': self.affected_files,
            'details': self.details
        }

@dataclass
class VirusReport:
    """病毒扫描报告数据模型"""
    malware_count: int = 0
    suspicious_apps: List[str] = field(default_factory=list)
    threat_level: str = "LOW"
    quarantine_files: List[str] = field(default_factory=list)
    scan_time: Optional[datetime] = None
    virus_signatures_version: str = ""
    
    def __post_init__(self):
        if self.scan_time is None:
            self.scan_time = datetime.now()

@dataclass
class ResourceReport:
    """资源扫描报告数据模型"""
    missing_resources: List[str] = field(default_factory=list)
    corrupted_libraries: List[str] = field(default_factory=list)
    framework_issues: List[str] = field(default_factory=list)
    repair_available: bool = False
    scan_time: Optional[datetime] = None
    
    def __post_init__(self):
        if self.scan_time is None:
            self.scan_time = datetime.now()

@dataclass
class DiagnosticReport:
    """诊断报告数据模型"""
    device_id: str
    scan_time: datetime
    issues_found: List[Issue] = field(default_factory=list)
    system_health_score: int = 100
    virus_report: Optional[VirusReport] = None
    resource_report: Optional[ResourceReport] = None
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.scan_time is None:
            self.scan_time = datetime.now()
    
    @property
    def critical_issues_count(self) -> int:
        """统计关键问题数量"""
        return len([issue for issue in self.issues_found 
                   if issue.severity == IssueSeverity.CRITICAL])
    
    @property
    def high_issues_count(self) -> int:
        """统计高优先级问题数量"""
        return len([issue for issue in self.issues_found 
                   if issue.severity == IssueSeverity.HIGH])
    
    @property
    def total_issues_count(self) -> int:
        """总问题数量"""
        return len(self.issues_found)
    
    def get_issues_by_category(self, category: IssueCategory) -> List[Issue]:
        """按类别获取问题列表"""
        return [issue for issue in self.issues_found 
                if issue.category == category]

@dataclass
class RepairTask:
    """修复任务数据模型"""
    task_id: str
    device_id: str
    task_type: str
    status: TaskStatus = TaskStatus.PENDING
    progress: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    estimated_duration: int = 0
    logs: List[str] = field(default_factory=list)
    error_message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)  # 添加details字段
    
    def __post_init__(self):
        if self.start_time is None and self.status == TaskStatus.RUNNING:
            self.start_time = datetime.now()
    
    @property
    def duration(self) -> Optional[int]:
        """计算任务执行时长（秒）"""
        if self.start_time is None:
            return None
        end = self.end_time or datetime.now()
        return int((end - self.start_time).total_seconds())
    
    def add_log(self, message: str):
        """添加日志信息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")
    
    def start(self):
        """开始任务"""
        self.status = TaskStatus.RUNNING
        self.start_time = datetime.now()
        self.add_log("任务开始执行")
    
    def complete(self):
        """完成任务"""
        self.status = TaskStatus.COMPLETED
        self.end_time = datetime.now()
        self.progress = 100
        self.add_log("任务执行完成")
    
    def fail(self, error_message: str):
        """任务失败"""
        self.status = TaskStatus.FAILED
        self.end_time = datetime.now()
        self.error_message = error_message
        self.add_log(f"任务执行失败: {error_message}")

@dataclass
class FileChecksum:
    """文件校验和数据模型"""
    file_path: str
    md5: str = ""
    sha256: str = ""
    size: int = 0
    last_modified: Optional[datetime] = None