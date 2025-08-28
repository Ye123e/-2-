#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据模型定义
包含设备信息、诊断报告等数据结构
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
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

class ThreatLevel(Enum):
    """威胁等级枚举"""
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EngineType(Enum):
    """检测引擎类型枚举"""
    SIGNATURE = "SIGNATURE"  # 特征检测
    YARA = "YARA"           # YARA规则
    CLAMAV = "CLAMAV"       # ClamAV引擎
    HEURISTIC = "HEURISTIC" # 启发式检测
    BEHAVIOR = "BEHAVIOR"   # 行为分析
    CLOUD = "CLOUD"         # 云查杀

class ThreatType(Enum):
    """威胁类型枚举"""
    MALWARE = "MALWARE"
    TROJAN = "TROJAN"
    VIRUS = "VIRUS"
    ADWARE = "ADWARE"
    SPYWARE = "SPYWARE"
    ROOTKIT = "ROOTKIT"
    BACKDOOR = "BACKDOOR"
    RANSOMWARE = "RANSOMWARE"
    SUSPICIOUS = "SUSPICIOUS"
    POTENTIALLY_UNWANTED = "POTENTIALLY_UNWANTED"

class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    INSECURE_PERMISSIONS = "INSECURE_PERMISSIONS"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"

class ScanMode(Enum):
    """扫描模式枚举"""
    QUICK = "QUICK"
    FULL = "FULL"
    CUSTOM = "CUSTOM"
    REALTIME = "REALTIME"

class RepairAction(Enum):
    """修复动作枚举"""
    QUARANTINE = "QUARANTINE"
    DELETE = "DELETE"
    CLEAN = "CLEAN"
    BLOCK = "BLOCK"
    PATCH = "PATCH"
    CONFIGURE = "CONFIGURE"
    UPDATE = "UPDATE"
    DISABLE = "DISABLE"

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


@dataclass
class MalwareInfo:
    """恶意软件信息数据模型"""
    threat_id: str
    threat_name: str
    package_name: str
    file_path: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    engine_type: EngineType
    confidence: float
    file_hash: str = ""
    file_size: int = 0
    signature_match: str = ""
    first_seen: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_updated is None:
            self.last_updated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'threat_id': self.threat_id,
            'threat_name': self.threat_name,
            'package_name': self.package_name,
            'file_path': self.file_path,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'engine_type': self.engine_type.value,
            'confidence': self.confidence,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'signature_match': self.signature_match,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'description': self.description,
            'metadata': self.metadata
        }


@dataclass
class VulnerabilityInfo:
    """漏洞信息数据模型"""
    vulnerability_id: str
    cve_id: str = ""
    title: str = ""
    description: str = ""
    vulnerability_type: VulnerabilityType = VulnerabilityType.CONFIGURATION_ERROR
    severity_level: ThreatLevel = ThreatLevel.MEDIUM
    cvss_score: float = 0.0
    affected_component: str = ""
    affected_version: str = ""
    patch_available: bool = False
    exploit_available: bool = False
    discovery_date: Optional[datetime] = None
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.discovery_date is None:
            self.discovery_date = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'vulnerability_id': self.vulnerability_id,
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'vulnerability_type': self.vulnerability_type.value,
            'severity_level': self.severity_level.value,
            'cvss_score': self.cvss_score,
            'affected_component': self.affected_component,
            'affected_version': self.affected_version,
            'patch_available': self.patch_available,
            'exploit_available': self.exploit_available,
            'discovery_date': self.discovery_date.isoformat() if self.discovery_date else None,
            'remediation_steps': self.remediation_steps,
            'references': self.references,
            'metadata': self.metadata
        }


@dataclass
class ThreatIntelligence:
    """威胁情报数据模型"""
    threat_id: str
    source: str
    confidence_level: float
    threat_type: ThreatType
    threat_level: ThreatLevel
    threat_indicators: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    attribution: str = ""
    campaign_name: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    ttps: List[str] = field(default_factory=list)  # Tactics, Techniques, and Procedures
    iocs: Dict[str, List[str]] = field(default_factory=dict)  # Indicators of Compromise
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'threat_id': self.threat_id,
            'source': self.source,
            'confidence_level': self.confidence_level,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'threat_indicators': self.threat_indicators,
            'mitigation_strategies': self.mitigation_strategies,
            'attribution': self.attribution,
            'campaign_name': self.campaign_name,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'ttps': self.ttps,
            'iocs': self.iocs,
            'metadata': self.metadata
        }


@dataclass
class ScanResult:
    """扫描结果数据模型"""
    scan_id: str
    device_id: str
    scan_mode: ScanMode
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    total_files_scanned: int = 0
    threats_found: int = 0
    vulnerabilities_found: int = 0
    malware_list: List[MalwareInfo] = field(default_factory=list)
    vulnerability_list: List[VulnerabilityInfo] = field(default_factory=list)
    scan_paths: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    scan_summary: str = ""
    performance_stats: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def scan_duration(self) -> Optional[float]:
        """获取扫描时长（秒）"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def is_completed(self) -> bool:
        """判断扫描是否完成"""
        return self.status in ["completed", "failed", "cancelled"]
    
    def add_malware(self, malware: MalwareInfo):
        """添加恶意软件检测结果"""
        self.malware_list.append(malware)
        self.threats_found = len(self.malware_list)
    
    def add_vulnerability(self, vulnerability: VulnerabilityInfo):
        """添加漏洞检测结果"""
        self.vulnerability_list.append(vulnerability)
        self.vulnerabilities_found = len(self.vulnerability_list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'scan_id': self.scan_id,
            'device_id': self.device_id,
            'scan_mode': self.scan_mode.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'total_files_scanned': self.total_files_scanned,
            'threats_found': self.threats_found,
            'vulnerabilities_found': self.vulnerabilities_found,
            'malware_list': [malware.to_dict() for malware in self.malware_list],
            'vulnerability_list': [vuln.to_dict() for vuln in self.vulnerability_list],
            'scan_paths': self.scan_paths,
            'excluded_paths': self.excluded_paths,
            'scan_summary': self.scan_summary,
            'performance_stats': self.performance_stats,
            'metadata': self.metadata
        }


@dataclass
class RepairPlan:
    """修复计划数据模型"""
    plan_id: str
    device_id: str
    scan_result_id: str
    creation_time: datetime
    repair_items: List['RepairItem'] = field(default_factory=list)
    estimated_time: int = 0  # 预估时间（秒）
    risk_level: ThreatLevel = ThreatLevel.LOW
    requires_confirmation: bool = True
    backup_required: bool = True
    status: str = "pending"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_repair_item(self, item: 'RepairItem'):
        """添加修复项目"""
        self.repair_items.append(item)
        self.estimated_time += item.estimated_time
        # 更新风险等级
        if item.risk_level.value > self.risk_level.value:
            self.risk_level = item.risk_level
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'plan_id': self.plan_id,
            'device_id': self.device_id,
            'scan_result_id': self.scan_result_id,
            'creation_time': self.creation_time.isoformat(),
            'repair_items': [item.to_dict() for item in self.repair_items],
            'estimated_time': self.estimated_time,
            'risk_level': self.risk_level.value,
            'requires_confirmation': self.requires_confirmation,
            'backup_required': self.backup_required,
            'status': self.status,
            'metadata': self.metadata
        }


@dataclass
class RepairItem:
    """修复项目数据模型"""
    item_id: str
    item_type: str  # malware_removal, vulnerability_patch, config_fix
    target_path: str
    action: RepairAction
    description: str
    estimated_time: int = 0  # 预估时间（秒）
    risk_level: ThreatLevel = ThreatLevel.LOW
    requires_root: bool = False
    backup_path: str = ""
    commands: List[str] = field(default_factory=list)
    verification_commands: List[str] = field(default_factory=list)
    rollback_commands: List[str] = field(default_factory=list)
    status: str = "pending"
    result_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'item_id': self.item_id,
            'item_type': self.item_type,
            'target_path': self.target_path,
            'action': self.action.value,
            'description': self.description,
            'estimated_time': self.estimated_time,
            'risk_level': self.risk_level.value,
            'requires_root': self.requires_root,
            'backup_path': self.backup_path,
            'commands': self.commands,
            'verification_commands': self.verification_commands,
            'rollback_commands': self.rollback_commands,
            'status': self.status,
            'result_message': self.result_message,
            'metadata': self.metadata
        }


# 更新导出列表
__all__ = [
    # 枚举类
    'ConnectionType', 'IssueCategory', 'IssueSeverity', 'TaskStatus',
    'ThreatLevel', 'EngineType', 'ThreatType', 'VulnerabilityType', 
    'ScanMode', 'RepairAction',
    # 数据模型类
    'DeviceInfo', 'Issue', 'VirusReport', 'ResourceReport', 
    'DiagnosticReport', 'RepairTask', 'FileChecksum',
    # 威胁检测相关模型
    'MalwareInfo', 'VulnerabilityInfo', 'ThreatIntelligence',
    'ScanResult', 'RepairPlan', 'RepairItem',
    # 安全事件与防护模型
    'SecurityEvent', 'ThreatAssessment', 'QuarantineRecord',
    'BackupRecord', 'PatchInfo', 'ProtectionRule',
    # 系统管理模型
    'ScanProfile', 'SystemReport'
]
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


@dataclass
class SecurityEvent:
    """安全事件数据模型"""
    event_id: str
    event_type: str  # FILE_CREATED, PROCESS_STARTED, etc.
    timestamp: datetime
    device_id: str
    source: str  # 文件路径、进程名等
    threat_level: ThreatLevel
    action_taken: Optional[str] = None
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'device_id': self.device_id,
            'source': self.source,
            'threat_level': self.threat_level.value,
            'action_taken': self.action_taken,
            'description': self.description,
            'details': self.details
        }


@dataclass
class ThreatAssessment:
    """威胁评估数据模型"""
    assessment_id: str
    target_package: str
    risk_score: float
    threat_level: ThreatLevel
    threat_categories: List[str] = field(default_factory=list)
    security_indicators: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_actions: List[Dict[str, Any]] = field(default_factory=list)
    assessment_time: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'assessment_id': self.assessment_id,
            'target_package': self.target_package,
            'risk_score': self.risk_score,
            'threat_level': self.threat_level.value,
            'threat_categories': self.threat_categories,
            'security_indicators': self.security_indicators,
            'mitigation_actions': self.mitigation_actions,
            'assessment_time': self.assessment_time.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class QuarantineRecord:
    """隔离记录数据模型"""
    record_id: str
    file_path: str
    quarantine_path: str
    quarantine_time: datetime
    threat_info: MalwareInfo
    quarantine_reason: str
    file_hash: str = ""
    file_size: int = 0
    restoration_available: bool = True
    status: str = "active"  # active, restored, deleted
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'record_id': self.record_id,
            'file_path': self.file_path,
            'quarantine_path': self.quarantine_path,
            'quarantine_time': self.quarantine_time.isoformat(),
            'threat_info': self.threat_info.to_dict(),
            'quarantine_reason': self.quarantine_reason,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'restoration_available': self.restoration_available,
            'status': self.status,
            'metadata': self.metadata
        }


@dataclass
class BackupRecord:
    """备份记录数据模型"""
    backup_id: str
    device_id: str
    backup_type: str  # full, incremental, snapshot
    backup_path: str
    creation_time: datetime
    backup_size: int = 0
    checksum: str = ""
    description: str = ""
    restore_commands: List[str] = field(default_factory=list)
    expiry_date: Optional[datetime] = None
    status: str = "active"  # active, expired, corrupted
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'backup_id': self.backup_id,
            'device_id': self.device_id,
            'backup_type': self.backup_type,
            'backup_path': self.backup_path,
            'creation_time': self.creation_time.isoformat(),
            'backup_size': self.backup_size,
            'checksum': self.checksum,
            'description': self.description,
            'restore_commands': self.restore_commands,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'status': self.status,
            'metadata': self.metadata
        }


@dataclass
class PatchInfo:
    """补丁信息数据模型"""
    patch_id: str
    name: str
    version: str
    patch_type: str  # SECURITY, SYSTEM, APPLICATION, FIRMWARE
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    size: int
    download_url: str
    checksum: str
    dependencies: List[str] = field(default_factory=list)
    status: str = "AVAILABLE"
    install_date: Optional[datetime] = None
    backup_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'patch_id': self.patch_id,
            'name': self.name,
            'version': self.version,
            'patch_type': self.patch_type,
            'description': self.description,
            'severity': self.severity,
            'size': self.size,
            'download_url': self.download_url,
            'checksum': self.checksum,
            'dependencies': self.dependencies,
            'status': self.status,
            'install_date': self.install_date.isoformat() if self.install_date else None,
            'backup_path': self.backup_path,
            'metadata': self.metadata
        }


@dataclass
class ProtectionRule:
    """保护规则数据模型"""
    rule_id: str
    name: str
    description: str
    rule_type: str  # WHITELIST, BLACKLIST, BEHAVIOR, etc.
    event_types: List[str]
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    enabled: bool = True
    priority: int = 50
    created_time: datetime = field(default_factory=datetime.now)
    modified_time: datetime = field(default_factory=datetime.now)
    execution_count: int = 0
    last_execution: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'rule_type': self.rule_type,
            'event_types': self.event_types,
            'conditions': self.conditions,
            'actions': self.actions,
            'enabled': self.enabled,
            'priority': self.priority,
            'created_time': self.created_time.isoformat(),
            'modified_time': self.modified_time.isoformat(),
            'execution_count': self.execution_count,
            'last_execution': self.last_execution.isoformat() if self.last_execution else None,
            'metadata': self.metadata
        }


@dataclass
class ScanProfile:
    """扫描配置文件数据模型"""
    profile_id: str
    name: str
    scan_mode: ScanMode
    scan_paths: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(default_factory=list)
    engines_enabled: List[str] = field(default_factory=list)
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    scan_archives: bool = True
    scan_encrypted: bool = False
    realtime_protection: bool = False
    schedule_enabled: bool = False
    schedule_cron: str = ""
    created_time: datetime = field(default_factory=datetime.now)
    modified_time: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'profile_id': self.profile_id,
            'name': self.name,
            'scan_mode': self.scan_mode.value,
            'scan_paths': self.scan_paths,
            'excluded_paths': self.excluded_paths,
            'excluded_extensions': self.excluded_extensions,
            'engines_enabled': self.engines_enabled,
            'max_file_size': self.max_file_size,
            'scan_archives': self.scan_archives,
            'scan_encrypted': self.scan_encrypted,
            'realtime_protection': self.realtime_protection,
            'schedule_enabled': self.schedule_enabled,
            'schedule_cron': self.schedule_cron,
            'created_time': self.created_time.isoformat(),
            'modified_time': self.modified_time.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class SystemReport:
    """系统报告数据模型"""
    report_id: str
    device_id: str
    report_type: str  # scan_report, security_report, performance_report
    generation_time: datetime
    data: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    export_formats: List[str] = field(default_factory=list)  # pdf, html, json, csv
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'report_id': self.report_id,
            'device_id': self.device_id,
            'report_type': self.report_type,
            'generation_time': self.generation_time.isoformat(),
            'data': self.data,
            'summary': self.summary,
            'recommendations': self.recommendations,
            'export_formats': self.export_formats,
            'metadata': self.metadata
        }