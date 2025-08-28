#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
病毒扫描引擎 - 增强版
集成多种检测引擎和YARA规则支持的病毒扫描系统
"""

import os
import sys
import json
import hashlib
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Callable, Set, Any, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import (
    DeviceInfo, VirusReport, Issue, IssueCategory, IssueSeverity,
    ThreatLevel, MalwareInfo, ThreatAssessment, ThreatType, EngineType
)
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore
    YARA_AVAILABLE = False

try:
    import pyclamd  # type: ignore
    CLAMAV_AVAILABLE = True
except ImportError:
    pyclamd = None  # type: ignore
    CLAMAV_AVAILABLE = False


class YaraEngine(LoggerMixin):
    """YARA规则引擎"""
    
    def __init__(self, rules_path: str = "data/yara_rules"):
        """
        初始化YARA引擎
        
        Args:
            rules_path: YARA规则文件目录
        """
        self.rules_path = Path(rules_path)
        self.rules_path.mkdir(parents=True, exist_ok=True)
        self.compiled_rules: Optional[Any] = None  # yara.Rules when available
        self.rules_timestamp = 0
        self._initialize_default_rules()
        self.load_rules()
    
    def _initialize_default_rules(self):
        """初始化默认YARA规则"""
        default_rules = """
        rule Android_Malware_Generic {
            meta:
                description = "通用Android恶意软件检测规则"
                author = "Android Security Scanner"
                
            strings:
                $malware1 = "android.permission.SEND_SMS"
                $malware2 = "android.permission.READ_SMS" 
                $malware3 = "android.permission.RECEIVE_SMS"
                $suspicious1 = /fake.*bank/i
                $suspicious2 = /trojan/i
                $suspicious3 = /malware/i
                
            condition:
                ($malware1 and $malware2 and $malware3) or any of ($suspicious*)
        }
        
        rule Android_Trojan_Banking {
            meta:
                description = "Android银行木马检测"
                
            strings:
                $bank1 = "com.android.vending.billing"
                $bank2 = "android.permission.SYSTEM_ALERT_WINDOW"
                $overlay = "TYPE_APPLICATION_OVERLAY"
                
            condition:
                $bank1 and $bank2 and $overlay
        }
        
        rule Android_Spyware_Location {
            meta:
                description = "Android间谍软件 - 位置跟踪"
                
            strings:
                $location1 = "android.permission.ACCESS_FINE_LOCATION"
                $location2 = "android.permission.ACCESS_COARSE_LOCATION"
                $network = "android.permission.INTERNET"
                $stealth = "android.permission.HIDE_OVERLAY_WINDOWS"
                
            condition:
                ($location1 or $location2) and $network and $stealth
        }
        """
        
        rules_file = self.rules_path / "android_malware.yar"
        if not rules_file.exists():
            with open(rules_file, 'w', encoding='utf-8') as f:
                f.write(default_rules)
    
    def load_rules(self) -> bool:
        """加载YARA规则"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA未安装，跳过规则加载")
            return False
        
        try:
            rule_files = list(self.rules_path.glob("*.yar")) + list(self.rules_path.glob("*.yara"))
            if not rule_files:
                self.logger.warning("未找到YARA规则文件")
                return False
            
            # 检查规则文件是否有更新
            latest_timestamp = max(f.stat().st_mtime for f in rule_files)
            if self.compiled_rules and latest_timestamp <= self.rules_timestamp:
                return True
            
            # 编译规则
            rule_dict = {}
            for rule_file in rule_files:
                rule_dict[str(rule_file)] = str(rule_file)
            
            self.compiled_rules = yara.compile(filepaths=rule_dict) if yara else None  # type: ignore
            self.rules_timestamp = latest_timestamp
            
            self.logger.info(f"成功加载 {len(rule_files)} 个YARA规则文件")
            return True
            
        except Exception as e:
            self.logger.error(f"加载YARA规则失败: {e}")
            return False
    
    def scan_file(self, file_path: str) -> List[Any]:  # List[yara.Match] when available
        """扫描文件"""
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(file_path)
            return matches
        except Exception as e:
            self.logger.error(f"YARA扫描文件失败 {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes) -> List[Any]:  # List[yara.Match] when available
        """扫描数据"""
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            return matches
        except Exception as e:
            self.logger.error(f"YARA扫描数据失败: {e}")
            return []


class ClamAVEngine(LoggerMixin):
    """ClamAV杀毒引擎"""
    
    def __init__(self, socket_path: str = "/tmp/clamd.socket"):
        """
        初始化ClamAV引擎
        
        Args:
            socket_path: ClamAV守护进程socket路径
        """
        self.socket_path = socket_path
        self.clamd_socket: Optional[Any] = None  # pyclamd socket when available
        self._initialize_connection()
    
    def _initialize_connection(self):
        """初始化ClamAV连接"""
        if not CLAMAV_AVAILABLE:
            self.logger.warning("pyclamd未安装，无法使用ClamAV引擎")
            return
        
        try:
            # 尝试连接Unix socket
            if os.path.exists(self.socket_path):
                self.clamd_socket = pyclamd.ClamdUnixSocket(self.socket_path)  # type: ignore
            else:
                # 尝试网络连接
                self.clamd_socket = pyclamd.ClamdNetworkSocket()  # type: ignore
            
            # 测试连接
            if self.clamd_socket and self.clamd_socket.ping():  # type: ignore
                self.logger.info("ClamAV引擎连接成功")
            else:
                self.clamd_socket = None
                self.logger.warning("ClamAV守护进程未运行")
                
        except Exception as e:
            self.logger.error(f"ClamAV连接失败: {e}")
            self.clamd_socket = None
    
    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """扫描文件"""
        if not self.clamd_socket:
            return None
        
        try:
            result = self.clamd_socket.scan_file(file_path)
            return result
        except Exception as e:
            self.logger.error(f"ClamAV扫描文件失败 {file_path}: {e}")
            return None
    
    def update_database(self) -> bool:
        """更新病毒库"""
        if not self.clamd_socket:
            return False
        
        try:
            self.clamd_socket.reload()
            self.logger.info("ClamAV病毒库更新完成")
            return True
        except Exception as e:
            self.logger.error(f"ClamAV病毒库更新失败: {e}")
            return False


class HeuristicEngine(LoggerMixin):
    """启发式检测引擎"""
    
    def __init__(self):
        """初始化启发式引擎"""
        # 行为模式定义
        self.behavior_patterns = {
            'permission_abuse': {
                'patterns': [
                    ['SEND_SMS', 'READ_CONTACTS', 'RECORD_AUDIO'],
                    ['DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW', 'INTERNET'],
                    ['ACCESS_FINE_LOCATION', 'SEND_SMS', 'INTERNET']
                ],
                'weight': 0.8
            },
            'suspicious_naming': {
                'patterns': [
                    r'.*fake.*', r'.*trojan.*', r'.*malware.*',
                    r'com\.android\..*fake.*', r'.*\.virus\..*'
                ],
                'weight': 0.6
            },
            'packing_indicators': {
                'indicators': [
                    'high_entropy', 'encrypted_strings', 'anti_debug',
                    'vm_detection', 'emulator_detection'
                ],
                'weight': 0.7
            }
        }
    
    def analyze_permissions(self, permissions: List[str]) -> Tuple[float, List[str]]:
        """分析权限风险"""
        risk_score = 0.0
        risk_reasons = []
        
        permission_set = set(perm.split('.')[-1] for perm in permissions)
        
        for pattern in self.behavior_patterns['permission_abuse']['patterns']:
            if set(pattern).issubset(permission_set):
                risk_score = max(risk_score, self.behavior_patterns['permission_abuse']['weight'])
                risk_reasons.append(f"检测到危险权限组合: {', '.join(pattern)}")
        
        return risk_score, risk_reasons
    
    def analyze_package_name(self, package_name: str) -> Tuple[float, List[str]]:
        """分析包名风险"""
        import re
        
        risk_score = 0.0
        risk_reasons = []
        
        for pattern in self.behavior_patterns['suspicious_naming']['patterns']:
            if re.match(pattern, package_name, re.IGNORECASE):
                risk_score = self.behavior_patterns['suspicious_naming']['weight']
                risk_reasons.append(f"可疑包名模式: {pattern}")
                break
        
        return risk_score, risk_reasons
    
    def analyze_behavior(self, behavior_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        """分析行为风险"""
        risk_score = 0.0
        risk_reasons = []
        
        # 检查网络行为
        if behavior_data.get('suspicious_connections'):
            risk_score += 0.3
            risk_reasons.append("检测到可疑网络连接")
        
        # 检查文件操作
        if behavior_data.get('system_file_modification'):
            risk_score += 0.4
            risk_reasons.append("尝试修改系统文件")
        
        # 检查进程行为
        if behavior_data.get('privilege_escalation'):
            risk_score += 0.5
            risk_reasons.append("尝试权限提升")
        
        return min(risk_score, 1.0), risk_reasons


class VirusScanEngine(LoggerMixin):
    """增强版病毒扫描引擎"""
    
    def __init__(self, 
                 device_manager: DeviceManager,
                 yara_rules_path: str = "data/yara_rules",
                 signature_db_path: str = "data/virus_signatures"):
        """
        初始化病毒扫描引擎
        
        Args:
            device_manager: 设备管理器
            yara_rules_path: YARA规则路径
            signature_db_path: 病毒特征库路径
        """
        self.device_manager = device_manager
        self.signature_db_path = Path(signature_db_path)
        self.signature_db_path.mkdir(parents=True, exist_ok=True)
        
        # 初始化各个引擎
        self.yara_engine = YaraEngine(yara_rules_path) if YARA_AVAILABLE else None
        self.clamav_engine = ClamAVEngine() if CLAMAV_AVAILABLE else None
        self.heuristic_engine = HeuristicEngine()
        
        # 扫描配置
        self.scan_options = {
            'use_yara': YARA_AVAILABLE,
            'use_clamav': CLAMAV_AVAILABLE and self.clamav_engine and self.clamav_engine.clamd_socket,
            'use_heuristic': True,
            'max_threads': 4,
            'timeout': 300  # 5分钟超时
        }
        
        # 进度回调
        self.progress_callbacks: List[Callable[[int, str], None]] = []
        
        # 扫描统计
        self.scan_stats = {
            'files_scanned': 0,
            'malware_detected': 0,
            'suspicious_files': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }
        
        self.logger.info(f"病毒扫描引擎初始化完成 - YARA: {self.scan_options['use_yara']}, ClamAV: {self.scan_options['use_clamav']}")
    
    def add_progress_callback(self, callback: Callable[[int, str], None]):
        """添加进度回调"""
        self.progress_callbacks.append(callback)
    
    def _update_progress(self, progress: int, message: str):
        """更新扫描进度"""
        for callback in self.progress_callbacks:
            try:
                callback(progress, message)
            except Exception as e:
                self.logger.error(f"进度回调执行失败: {e}")
    
    def scan_application(self, device_id: str, app_info: Dict[str, Any]) -> ThreatAssessment:
        """
        扫描单个应用
        
        Args:
            device_id: 设备ID
            app_info: 应用信息
            
        Returns:
            恶意软件检测信息
        """
        malware_info = ThreatAssessment(
            app_package=app_info.get('package_name', 'unknown'),
            threat_level=ThreatLevel.LOW,
            risk_score=0.0
        )
        
        package_name = app_info.get('package_name', '')
        permissions = app_info.get('permissions', [])
        
        try:
            # 1. 启发式分析
            if self.scan_options['use_heuristic']:
                perm_risk, perm_reasons = self.heuristic_engine.analyze_permissions(permissions)
                pkg_risk, pkg_reasons = self.heuristic_engine.analyze_package_name(package_name)
                
                total_heuristic_risk = max(perm_risk, pkg_risk)
                if total_heuristic_risk > 0.5:
                    malware_info.threat_categories.append(ThreatType.POTENTIALLY_UNWANTED)
                    malware_info.risk_score = max(malware_info.risk_score, total_heuristic_risk)
                    malware_info.details['heuristic_detection'] = {
                        'risk_score': total_heuristic_risk,
                        'reasons': perm_reasons + pkg_reasons
                    }
            
            # 2. YARA规则扫描
            if self.scan_options['use_yara'] and self.yara_engine:
                # 获取APK文件路径并扫描
                apk_path = self._get_apk_path(device_id, package_name)
                if apk_path:
                    yara_matches = self.yara_engine.scan_file(apk_path)
                    if yara_matches:
                        malware_info.threat_categories.append(ThreatType.MALWARE)
                        malware_info.risk_score = max(malware_info.risk_score, 0.8)
                        rule_names = [match.rule for match in yara_matches if hasattr(match, 'rule')]
                        malware_info.details['yara_detection'] = {
                            'matched_rules': rule_names
                        }
            
            # 3. ClamAV扫描
            if self.scan_options['use_clamav'] and self.clamav_engine:
                apk_path = self._get_apk_path(device_id, package_name)
                if apk_path:
                    clamav_result = self.clamav_engine.scan_file(apk_path)
                    if clamav_result and any('FOUND' in str(v) for v in clamav_result.values()):
                        malware_info.threat_categories.append(ThreatType.MALWARE)
                        malware_info.risk_score = 1.0
                        malware_info.details['clamav_detection'] = {
                            'result': clamav_result
                        }
            
            # 4. 确定威胁级别
            if malware_info.risk_score >= 0.8:
                malware_info.threat_level = ThreatLevel.CRITICAL
            elif malware_info.risk_score >= 0.6:
                malware_info.threat_level = ThreatLevel.HIGH
            elif malware_info.risk_score >= 0.3:
                malware_info.threat_level = ThreatLevel.MEDIUM
            
            # 5. 生成缓解措施
            if malware_info.threat_level != ThreatLevel.LOW:
                from ..models import MitigationAction, ActionType, Priority
                malware_info.mitigation_actions = [
                    MitigationAction(ActionType.DELETE, Priority.HIGH, "建议立即卸载该应用"),
                    MitigationAction(ActionType.MONITOR, Priority.MEDIUM, "检查设备是否存在其他恶意软件"),
                    MitigationAction(ActionType.ALERT, Priority.MEDIUM, "更改相关账户密码"),
                    MitigationAction(ActionType.MONITOR, Priority.LOW, "扫描设备中的敏感数据")
                ]
            
            self.scan_stats['files_scanned'] += 1
            if malware_info.threat_level != ThreatLevel.LOW:
                self.scan_stats['malware_detected'] += 1
            
        except Exception as e:
            self.logger.error(f"扫描应用失败 {package_name}: {e}")
        
        return malware_info
    
    def _get_apk_path(self, device_id: str, package_name: str) -> Optional[str]:
        """获取应用APK文件路径"""
        try:
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm path {package_name}"
            )
            if result and result.startswith('package:'):
                return result.replace('package:', '').strip()
        except Exception as e:
            self.logger.error(f"获取APK路径失败 {package_name}: {e}")
        
        return None
    
    def scan_device(self, device_id: str, scan_options: Optional[Dict[str, Any]] = None) -> Optional[VirusReport]:
        """
        扫描设备
        
        Args:
            device_id: 设备ID  
            scan_options: 扫描选项
            
        Returns:
            病毒扫描报告
        """
        device_info = self.device_manager.get_device(device_id)
        if not device_info:
            self.logger.error(f"设备未找到: {device_id}")
            return None
        
        # 重置统计信息
        self.scan_stats = {
            'files_scanned': 0,
            'malware_detected': 0,
            'suspicious_files': 0,
            'scan_start_time': datetime.now(),
            'scan_end_time': None
        }
        
        self._update_progress(0, "开始病毒扫描...")
        
        try:
            # 获取设备上的应用列表
            self._update_progress(10, "获取应用列表...")
            apps_result = self.device_manager.adb_manager.execute_command(
                device_id, "pm list packages -f"
            )
            
            if not apps_result:
                self.logger.error("获取应用列表失败")
                return None
            
            # 解析应用信息
            app_packages = []
            for line in apps_result.split('\n'):
                if line.startswith('package:'):
                    parts = line.split('=')
                    if len(parts) == 2:
                        app_packages.append(parts[1].strip())
            
            total_apps = len(app_packages)
            self.logger.info(f"找到 {total_apps} 个应用程序")
            
            # 并行扫描应用
            detected_malware: List[ThreatAssessment] = []
            with ThreadPoolExecutor(max_workers=self.scan_options['max_threads']) as executor:
                futures = {}
                
                for i, package_name in enumerate(app_packages):
                    # 获取应用详细信息
                    app_info = self._get_app_info(device_id, package_name)
                    if app_info:
                        future = executor.submit(self.scan_application, device_id, app_info)
                        futures[future] = (i, package_name)
                
                # 收集结果
                for future in as_completed(futures, timeout=self.scan_options['timeout']):
                    i, package_name = futures[future]
                    progress = int((i + 1) / total_apps * 80) + 10
                    
                    try:
                        malware_info = future.result()
                        if malware_info.threat_level != ThreatLevel.LOW:
                            detected_malware.append(malware_info)
                            self._update_progress(progress, f"检测到威胁: {package_name}")
                        else:
                            self._update_progress(progress, f"扫描完成: {package_name}")
                    except Exception as e:
                        self.logger.error(f"扫描应用异常 {package_name}: {e}")
            
            # 生成扫描报告
            self.scan_stats['scan_end_time'] = datetime.now()
            scan_duration = (self.scan_stats['scan_end_time'] - self.scan_stats['scan_start_time']).total_seconds()
            
            threat_level = ThreatLevel.LOW
            if detected_malware:
                max_risk = max(m.risk_score for m in detected_malware)
                if max_risk >= 0.8:
                    threat_level = ThreatLevel.CRITICAL
                elif max_risk >= 0.6:
                    threat_level = ThreatLevel.HIGH
                elif max_risk >= 0.3:
                    threat_level = ThreatLevel.MEDIUM
            
            # 创建简化的VirusReport - 基于实际的类定义
            report = VirusReport(
                malware_count=len(detected_malware),
                suspicious_apps=[m.app_package for m in detected_malware if m.threat_level == ThreatLevel.MEDIUM],
                threat_level=threat_level.value,
                quarantine_files=[]
            )
            
            # 将详细信息存储在一个属性中（如果需要的话）
            if hasattr(report, 'scan_summary'):
                report.scan_summary = {  # type: ignore
                    'device_id': device_id,
                    'total_apps': total_apps,
                    'scan_duration': scan_duration,
                    'engines_used': [engine for engine, enabled in self.scan_options.items() 
                                   if enabled and engine.startswith('use_')],
                    'scan_stats': self.scan_stats,
                    'detected_threats': detected_malware
                }
            
            self._update_progress(100, f"扫描完成，发现 {len(detected_malware)} 个威胁")
            self.logger.info(f"设备扫描完成: {len(detected_malware)} 个威胁，耗时 {scan_duration:.1f} 秒")
            
            return report
            
        except Exception as e:
            self.logger.error(f"设备扫描失败: {e}")
            return None
    
    def _get_app_info(self, device_id: str, package_name: str) -> Optional[Dict[str, Any]]:
        """获取应用详细信息"""
        try:
            # 获取权限信息
            perms_result = self.device_manager.adb_manager.execute_command(
                device_id, f"dumpsys package {package_name} | grep permission"
            )
            
            permissions = []
            if perms_result:
                for line in perms_result.split('\n'):
                    if 'android.permission' in line:
                        perm = line.strip().split(':')[0] if ':' in line else line.strip()
                        permissions.append(perm)
            
            return {
                'package_name': package_name,
                'permissions': permissions,
                'install_time': datetime.now()  # 简化版本
            }
            
        except Exception as e:
            self.logger.error(f"获取应用信息失败 {package_name}: {e}")
            return None
    
    def update_virus_signatures(self) -> bool:
        """更新病毒特征库"""
        success = True
        
        # 更新YARA规则
        if self.yara_engine:
            if not self.yara_engine.load_rules():
                success = False
        
        # 更新ClamAV病毒库
        if self.clamav_engine:
            if not self.clamav_engine.update_database():
                success = False
        
        return success
    
    def quarantine_malware(self, device_id: str, package_name: str) -> bool:
        """隔离恶意软件"""
        try:
            # 禁用应用
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm disable-user {package_name}"
            )
            
            if result and "disabled" in result.lower():
                self.logger.info(f"成功隔离恶意软件: {package_name}")
                return True
            else:
                self.logger.error(f"隔离失败: {package_name} - {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"隔离恶意软件失败: {e}")
            return False
    
    def remove_malware(self, device_id: str, package_name: str) -> bool:
        """移除恶意软件"""
        try:
            # 卸载应用
            result = self.device_manager.adb_manager.execute_command(
                device_id, f"pm uninstall {package_name}"
            )
            
            if result and "success" in result.lower():
                self.logger.info(f"成功移除恶意软件: {package_name}")
                return True
            else:
                self.logger.error(f"移除失败: {package_name} - {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"移除恶意软件失败: {e}")
            return False