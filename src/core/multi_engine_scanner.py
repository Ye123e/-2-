#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多引擎病毒扫描协调器
集成ClamAV、YARA、启发式检测等多个引擎
"""

import os
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..models import ThreatLevel, MalwareInfo, ScanResult
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

try:
    import pyclamd
    CLAMAV_AVAILABLE = True
except ImportError:
    pyclamd = None
    CLAMAV_AVAILABLE = False


@dataclass
class ScanJob:
    """扫描任务"""
    job_id: str
    target_type: str  # 'file', 'directory', 'app'
    target_path: str
    engines: List[str] = field(default_factory=list)
    priority: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    timeout: int = 300  # 5分钟超时


@dataclass
class EngineResult:
    """引擎检测结果"""
    engine_name: str
    scan_time: float
    threats_found: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class EnhancedClamAVEngine(LoggerMixin):
    """增强版ClamAV引擎"""
    
    def __init__(self):
        self.socket_path = "/tmp/clamd.socket"
        self.clamd_socket: Optional[Any] = None
        self.connection_timeout = 10
        self.scan_timeout = 300
        self.max_file_size = 200 * 1024 * 1024  # 200MB
        self.max_scan_time = 120  # 2分钟
        self._initialize()
    
    def _initialize(self):
        """初始化ClamAV连接"""
        if not CLAMAV_AVAILABLE:
            self.logger.warning("pyclamd未安装，ClamAV引擎不可用")
            return
        
        try:
            # Windows系统尝试TCP连接
            if os.name == 'nt':
                self.clamd_socket = pyclamd.ClamdNetworkSocket(
                    host='127.0.0.1', 
                    port=3310, 
                    timeout=self.connection_timeout
                )
            else:
                # Unix系统尝试socket连接
                if os.path.exists(self.socket_path):
                    self.clamd_socket = pyclamd.ClamdUnixSocket(
                        path=self.socket_path,
                        timeout=self.connection_timeout
                    )
                else:
                    self.clamd_socket = pyclamd.ClamdNetworkSocket(
                        host='127.0.0.1', 
                        port=3310, 
                        timeout=self.connection_timeout
                    )
            
            # 测试连接
            if self.clamd_socket.ping():
                version = self.clamd_socket.version()
                self.logger.info(f"ClamAV引擎已连接: {version}")
            else:
                self.clamd_socket = None
                
        except Exception as e:
            self.logger.warning(f"ClamAV连接失败: {e}")
            self.clamd_socket = None
    
    def scan_file(self, file_path: str) -> EngineResult:
        """扫描文件"""
        start_time = time.time()
        result = EngineResult(engine_name="ClamAV", scan_time=0)
        
        try:
            if not self.clamd_socket:
                result.success = False
                result.error_message = "ClamAV未连接"
                return result
            
            # 检查文件
            if not os.path.exists(file_path):
                result.success = False
                result.error_message = "文件不存在"
                return result
            
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                result.success = False
                result.error_message = f"文件过大: {file_size} bytes"
                return result
            
            # 执行扫描
            scan_result = self.clamd_socket.scan_file(file_path)
            
            if scan_result:
                for file_name, status in scan_result.items():
                    if len(status) >= 2 and status[0] == 'FOUND':
                        result.threats_found.append({
                            'file': file_name,
                            'threat_name': status[1],
                            'threat_type': 'malware',
                            'confidence': 0.9,
                            'engine': 'ClamAV'
                        })
            
            result.metadata = {
                'file_size': file_size,
                'scanned_files': 1
            }
            
        except Exception as e:
            self.logger.error(f"ClamAV扫描失败: {e}")
            result.success = False
            result.error_message = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def scan_buffer(self, data: bytes) -> EngineResult:
        """扫描内存数据"""
        start_time = time.time()
        result = EngineResult(engine_name="ClamAV", scan_time=0)
        
        try:
            if not self.clamd_socket:
                result.success = False
                result.error_message = "ClamAV未连接"
                return result
            
            if len(data) > self.max_file_size:
                result.success = False
                result.error_message = f"数据过大: {len(data)} bytes"
                return result
            
            # 执行扫描
            scan_result = self.clamd_socket.scan_stream(data)
            
            if scan_result and 'stream' in scan_result:
                status = scan_result['stream']
                if len(status) >= 2 and status[0] == 'FOUND':
                    result.threats_found.append({
                        'threat_name': status[1],
                        'threat_type': 'malware',
                        'confidence': 0.9,
                        'engine': 'ClamAV'
                    })
            
            result.metadata = {
                'data_size': len(data)
            }
            
        except Exception as e:
            self.logger.error(f"ClamAV内存扫描失败: {e}")
            result.success = False
            result.error_message = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def is_available(self) -> bool:
        """检查引擎是否可用"""
        return self.clamd_socket is not None


class EnhancedYaraEngine(LoggerMixin):
    """增强版YARA引擎"""
    
    def __init__(self, rules_path: str = "data/yara_rules"):
        self.rules_path = Path(rules_path)
        self.rules_path.mkdir(parents=True, exist_ok=True)
        self.compiled_rules: Optional[Any] = None
        self.rules_timestamp = 0
        self.rule_files: List[Path] = []
        self._initialize_rules()
        self.load_rules()
    
    def _initialize_rules(self):
        """初始化默认规则"""
        android_rules = '''
        rule Android_Malware_Permissions {
            meta:
                description = "Android恶意权限组合检测"
                author = "Security Scanner"
                
            strings:
                $sms1 = "android.permission.SEND_SMS"
                $sms2 = "android.permission.READ_SMS"
                $contact = "android.permission.READ_CONTACTS"
                $location = "android.permission.ACCESS_FINE_LOCATION"
                $admin = "android.permission.DEVICE_ADMIN"
                $overlay = "android.permission.SYSTEM_ALERT_WINDOW"
                
            condition:
                ($sms1 and $sms2 and $contact) or 
                ($admin and $overlay) or
                (3 of ($sms1, $sms2, $contact, $location))
        }
        
        rule Android_Banking_Trojan {
            meta:
                description = "Android银行木马特征"
                
            strings:
                $banking1 = "com.android.vending.billing"
                $banking2 = "overlay" nocase
                $banking3 = "accessibility" nocase
                $url1 = /https?:\\/\\/.*\\.(?:tk|ml|ga|cf)/ nocase
                
            condition:
                ($banking1 and $banking2) or
                ($banking3 and $url1) or
                2 of ($banking*)
        }
        
        rule Android_Spyware_Indicators {
            meta:
                description = "Android间谍软件指标"
                
            strings:
                $spy1 = "keylog" nocase
                $spy2 = "screenshot" nocase
                $spy3 = "record" nocase
                $spy4 = "monitor" nocase
                $crypto1 = { 41 45 53 2F }  // AES encryption
                $crypto2 = "encrypt" nocase
                
            condition:
                2 of ($spy*) or
                (1 of ($spy*) and 1 of ($crypto*))
        }
        '''
        
        # 创建Android恶意软件规则
        android_rules_file = self.rules_path / "android_malware.yar"
        if not android_rules_file.exists():
            with open(android_rules_file, 'w', encoding='utf-8') as f:
                f.write(android_rules)
        
        # 创建通用恶意软件规则
        generic_rules = '''
        rule Generic_Packer {
            meta:
                description = "通用加壳程序检测"
                
            strings:
                $upx1 = "UPX!"
                $upx2 = "UPX0"
                $aspack = "aPLib"
                $pecompact = "PECompact"
                
            condition:
                any of them
        }
        
        rule Suspicious_Strings {
            meta:
                description = "可疑字符串检测"
                
            strings:
                $sus1 = "keylogger" nocase
                $sus2 = "backdoor" nocase
                $sus3 = "rootkit" nocase
                $sus4 = "trojan" nocase
                $sus5 = "stealer" nocase
                
            condition:
                any of them
        }
        '''
        
        generic_rules_file = self.rules_path / "generic_malware.yar"
        if not generic_rules_file.exists():
            with open(generic_rules_file, 'w', encoding='utf-8') as f:
                f.write(generic_rules)
    
    def load_rules(self) -> bool:
        """加载YARA规则"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA未安装，引擎不可用")
            return False
        
        try:
            # 查找规则文件
            self.rule_files = list(self.rules_path.glob("*.yar")) + list(self.rules_path.glob("*.yara"))
            
            if not self.rule_files:
                self.logger.warning("未找到YARA规则文件")
                return False
            
            # 检查文件更新
            latest_timestamp = max(f.stat().st_mtime for f in self.rule_files)
            if self.compiled_rules and latest_timestamp <= self.rules_timestamp:
                return True
            
            # 编译规则
            rule_dict = {}
            for rule_file in self.rule_files:
                namespace = rule_file.stem
                rule_dict[namespace] = str(rule_file)
            
            self.compiled_rules = yara.compile(filepaths=rule_dict)
            self.rules_timestamp = latest_timestamp
            
            self.logger.info(f"YARA规则加载成功: {len(self.rule_files)} 个文件")
            return True
            
        except Exception as e:
            self.logger.error(f"YARA规则加载失败: {e}")
            return False
    
    def scan_file(self, file_path: str) -> EngineResult:
        """扫描文件"""
        start_time = time.time()
        result = EngineResult(engine_name="YARA", scan_time=0)
        
        try:
            if not self.compiled_rules:
                result.success = False
                result.error_message = "YARA规则未加载"
                return result
            
            # 执行扫描
            matches = self.compiled_rules.match(file_path, timeout=60)
            
            for match in matches:
                result.threats_found.append({
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': dict(match.meta),
                    'strings': [{'identifier': s.identifier, 'instances': len(s.instances)} 
                               for s in match.strings],
                    'threat_type': 'suspicious',
                    'confidence': 0.7,
                    'engine': 'YARA'
                })
            
            result.metadata = {
                'rules_count': len(self.rule_files),
                'matches_count': len(matches)
            }
            
        except Exception as e:
            self.logger.error(f"YARA扫描失败: {e}")
            result.success = False
            result.error_message = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def scan_data(self, data: bytes) -> EngineResult:
        """扫描数据"""
        start_time = time.time()
        result = EngineResult(engine_name="YARA", scan_time=0)
        
        try:
            if not self.compiled_rules:
                result.success = False
                result.error_message = "YARA规则未加载"
                return result
            
            matches = self.compiled_rules.match(data=data, timeout=60)
            
            for match in matches:
                result.threats_found.append({
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': dict(match.meta),
                    'threat_type': 'suspicious',
                    'confidence': 0.7,
                    'engine': 'YARA'
                })
            
            result.metadata = {
                'data_size': len(data),
                'matches_count': len(matches)
            }
            
        except Exception as e:
            self.logger.error(f"YARA数据扫描失败: {e}")
            result.success = False
            result.error_message = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def is_available(self) -> bool:
        """检查引擎是否可用"""
        return YARA_AVAILABLE and self.compiled_rules is not None


class SignatureEngine(LoggerMixin):
    """文件签名检测引擎"""
    
    def __init__(self, signatures_path: str = "data/signatures"):
        self.signatures_path = Path(signatures_path)
        self.signatures_path.mkdir(parents=True, exist_ok=True)
        self.malware_hashes: Set[str] = set()
        self.suspicious_hashes: Set[str] = set()
        self._load_signatures()
    
    def _load_signatures(self):
        """加载签名数据"""
        try:
            # 加载恶意文件哈希
            malware_file = self.signatures_path / "malware_hashes.txt"
            if malware_file.exists():
                with open(malware_file, 'r') as f:
                    for line in f:
                        hash_val = line.strip().lower()
                        if len(hash_val) == 64:  # SHA256
                            self.malware_hashes.add(hash_val)
            
            # 加载可疑文件哈希
            suspicious_file = self.signatures_path / "suspicious_hashes.txt"
            if suspicious_file.exists():
                with open(suspicious_file, 'r') as f:
                    for line in f:
                        hash_val = line.strip().lower()
                        if len(hash_val) == 64:
                            self.suspicious_hashes.add(hash_val)
                            
            self.logger.info(f"签名加载完成: 恶意{len(self.malware_hashes)}, 可疑{len(self.suspicious_hashes)}")
            
        except Exception as e:
            self.logger.error(f"签名加载失败: {e}")
    
    def scan_file(self, file_path: str) -> EngineResult:
        """扫描文件"""
        start_time = time.time()
        result = EngineResult(engine_name="Signature", scan_time=0)
        
        try:
            if not os.path.exists(file_path):
                result.success = False
                result.error_message = "文件不存在"
                return result
            
            # 计算文件哈希
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest().lower()
            
            # 检查哈希匹配
            if file_hash in self.malware_hashes:
                result.threats_found.append({
                    'hash': file_hash,
                    'threat_type': 'malware',
                    'confidence': 0.95,
                    'engine': 'Signature'
                })
            elif file_hash in self.suspicious_hashes:
                result.threats_found.append({
                    'hash': file_hash,
                    'threat_type': 'suspicious',
                    'confidence': 0.6,
                    'engine': 'Signature'
                })
            
            result.metadata = {
                'file_hash': file_hash,
                'file_size': os.path.getsize(file_path)
            }
            
        except Exception as e:
            self.logger.error(f"签名扫描失败: {e}")
            result.success = False
            result.error_message = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def is_available(self) -> bool:
        """检查引擎是否可用"""
        return len(self.malware_hashes) > 0 or len(self.suspicious_hashes) > 0


class MultiEngineScanCoordinator(LoggerMixin):
    """多引擎扫描协调器"""
    
    def __init__(self):
        # 初始化各个引擎
        self.clamav_engine = EnhancedClamAVEngine()
        self.yara_engine = EnhancedYaraEngine()
        self.signature_engine = SignatureEngine()
        
        # 扫描配置
        self.max_workers = 3
        self.scan_timeout = 300  # 5分钟
        
        # 统计信息
        self.scan_stats = {
            'total_scans': 0,
            'threats_found': 0,
            'engines_used': {
                'ClamAV': 0,
                'YARA': 0,
                'Signature': 0
            },
            'scan_times': []
        }
        
        # 检查可用引擎
        self.available_engines = self._check_available_engines()
        self.logger.info(f"可用扫描引擎: {', '.join(self.available_engines)}")
    
    def _check_available_engines(self) -> List[str]:
        """检查可用的扫描引擎"""
        available = []
        
        if self.clamav_engine.is_available():
            available.append('ClamAV')
        
        if self.yara_engine.is_available():
            available.append('YARA')
        
        if self.signature_engine.is_available():
            available.append('Signature')
        
        return available
    
    def scan_file(self, file_path: str, engines: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        使用多个引擎扫描文件
        
        Args:
            file_path: 文件路径
            engines: 要使用的引擎列表，None表示使用所有可用引擎
            
        Returns:
            综合扫描结果
        """
        start_time = time.time()
        
        if engines is None:
            engines = self.available_engines
        
        # 过滤可用引擎
        engines = [e for e in engines if e in self.available_engines]
        
        if not engines:
            return {
                'success': False,
                'error': '没有可用的扫描引擎',
                'file_path': file_path
            }
        
        # 并行执行扫描
        engine_results = {}
        with ThreadPoolExecutor(max_workers=len(engines)) as executor:
            futures = {}
            
            # 提交扫描任务
            for engine in engines:
                if engine == 'ClamAV':
                    future = executor.submit(self.clamav_engine.scan_file, file_path)
                elif engine == 'YARA':
                    future = executor.submit(self.yara_engine.scan_file, file_path)
                elif engine == 'Signature':
                    future = executor.submit(self.signature_engine.scan_file, file_path)
                else:
                    continue
                
                futures[future] = engine
            
            # 收集结果
            for future in as_completed(futures, timeout=self.scan_timeout):
                engine = futures[future]
                try:
                    result = future.result()
                    engine_results[engine] = result
                    self.scan_stats['engines_used'][engine] += 1
                except Exception as e:
                    self.logger.error(f"{engine}扫描异常: {e}")
                    engine_results[engine] = EngineResult(
                        engine_name=engine,
                        scan_time=0,
                        success=False,
                        error_message=str(e)
                    )
        
        # 汇总结果
        scan_result = self._aggregate_results(file_path, engine_results)
        scan_result['scan_duration'] = time.time() - start_time
        
        # 更新统计
        self.scan_stats['total_scans'] += 1
        self.scan_stats['scan_times'].append(scan_result['scan_duration'])
        if scan_result['threats_found'] > 0:
            self.scan_stats['threats_found'] += 1
        
        return scan_result
    
    def _aggregate_results(self, file_path: str, engine_results: Dict[str, EngineResult]) -> Dict[str, Any]:
        """汇总多引擎扫描结果"""
        all_threats = []
        successful_engines = []
        failed_engines = []
        total_scan_time = 0
        
        for engine, result in engine_results.items():
            if result.success:
                successful_engines.append(engine)
                all_threats.extend(result.threats_found)
                total_scan_time += result.scan_time
            else:
                failed_engines.append({
                    'engine': engine,
                    'error': result.error_message
                })
        
        # 威胁去重和评分
        unique_threats = self._deduplicate_threats(all_threats)
        
        # 计算总体威胁级别
        threat_level = self._calculate_threat_level(unique_threats)
        
        return {
            'file_path': file_path,
            'scan_time': datetime.now(),
            'success': len(successful_engines) > 0,
            'engines_used': successful_engines,
            'engines_failed': failed_engines,
            'threats_found': len(unique_threats),
            'threat_details': unique_threats,
            'threat_level': threat_level,
            'total_scan_time': total_scan_time,
            'metadata': {
                'engines_count': len(engine_results),
                'success_rate': len(successful_engines) / len(engine_results) if engine_results else 0
            }
        }
    
    def _deduplicate_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """威胁去重"""
        seen_threats = set()
        unique_threats = []
        
        for threat in threats:
            # 创建威胁标识
            threat_id = ""
            if 'threat_name' in threat:
                threat_id = threat['threat_name']
            elif 'rule_name' in threat:
                threat_id = threat['rule_name']
            elif 'hash' in threat:
                threat_id = threat['hash']
            else:
                threat_id = str(threat)
            
            if threat_id not in seen_threats:
                seen_threats.add(threat_id)
                unique_threats.append(threat)
        
        return unique_threats
    
    def _calculate_threat_level(self, threats: List[Dict[str, Any]]) -> str:
        """计算威胁级别"""
        if not threats:
            return "CLEAN"
        
        max_confidence = 0
        threat_types = set()
        
        for threat in threats:
            confidence = threat.get('confidence', 0)
            threat_type = threat.get('threat_type', 'unknown')
            
            max_confidence = max(max_confidence, confidence)
            threat_types.add(threat_type)
        
        # 根据置信度和威胁类型确定级别
        if 'malware' in threat_types and max_confidence >= 0.8:
            return "CRITICAL"
        elif 'malware' in threat_types or max_confidence >= 0.7:
            return "HIGH"
        elif max_confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """获取引擎统计信息"""
        avg_scan_time = sum(self.scan_stats['scan_times']) / len(self.scan_stats['scan_times']) if self.scan_stats['scan_times'] else 0
        
        return {
            'available_engines': self.available_engines,
            'scan_statistics': {
                **self.scan_stats,
                'average_scan_time': avg_scan_time
            },
            'engine_status': {
                'ClamAV': self.clamav_engine.is_available(),
                'YARA': self.yara_engine.is_available(), 
                'Signature': self.signature_engine.is_available()
            }
        }