#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络行为监控和代码结构分析模块
提供深度网络监控、代码静态分析和动态行为检测功能
"""

import json
import hashlib
import re
import threading
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from ..models import SecurityIndicator, IndicatorType, Severity
from ..utils.logger import LoggerMixin


@dataclass
class NetworkConnection:
    """网络连接信息"""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    state: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    data_transferred: int = 0


@dataclass  
class CodeStructureInfo:
    """代码结构信息"""
    file_path: str
    file_type: str
    size: int
    entropy: float
    api_calls: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)


class NetworkBehaviorMonitor(LoggerMixin):
    """网络行为监控器"""
    
    def __init__(self):
        """初始化网络行为监控器"""
        self.is_monitoring = False
        self.connection_history: List[NetworkConnection] = []
        self.suspicious_domains = {
            'malware-c2.com', 'evil-server.net', 'trojan-control.org',
            'phishing-site.com', 'fake-bank.net', 'suspicious-ads.com'
        }
        self.suspicious_ips = {'192.168.1.100', '10.0.0.50', '172.16.0.100'}
        self.malicious_ports = {1234, 4444, 5555, 6666, 31337, 1337}
        
        # 监控统计
        self.stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'blocked_connections': 0,
            'data_transferred': 0
        }
    
    def start_monitoring(self):
        """启动网络监控"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_network_activity)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info("网络行为监控已启动")
    
    def stop_monitoring(self):
        """停止网络监控"""
        self.is_monitoring = False
        self.logger.info("网络行为监控已停止")
    
    def _monitor_network_activity(self):
        """监控网络活动"""
        while self.is_monitoring:
            try:
                # 模拟网络连接监控
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"网络监控错误: {e}")
                time.sleep(10)
    
    def analyze_connection(self, connection: NetworkConnection) -> List[SecurityIndicator]:
        """分析网络连接"""
        indicators = []
        
        # 检查可疑域名
        if any(domain in connection.remote_address for domain in self.suspicious_domains):
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.NETWORK_ANOMALY,
                severity=Severity.HIGH,
                confidence=0.9,
                description=f"连接到可疑域名: {connection.remote_address}",
                evidence={'remote_address': connection.remote_address}
            ))
        
        # 检查可疑端口
        if connection.remote_port in self.malicious_ports:
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.NETWORK_ANOMALY,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description=f"使用可疑端口: {connection.remote_port}",
                evidence={'remote_port': connection.remote_port}
            ))
        
        return indicators
    
    def analyze_traffic_pattern(self, time_window: int = 3600) -> Dict[str, Any]:
        """分析流量模式"""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=time_window)
            recent_connections = [
                conn for conn in self.connection_history 
                if conn.timestamp > cutoff_time
            ]
            
            if not recent_connections:
                return {'pattern_type': 'no_activity', 'risk_score': 0.0}
            
            connection_frequency = len(recent_connections) / time_window * 3600
            unique_destinations = len(set(
                f"{conn.remote_address}:{conn.remote_port}"
                for conn in recent_connections
            ))
            
            # 计算风险评分
            risk_score = 0.0
            if connection_frequency > 100:
                risk_score += 0.3
            if unique_destinations > 20:
                risk_score += 0.4
            
            return {
                'pattern_type': 'analyzed',
                'risk_score': min(risk_score, 1.0),
                'connection_frequency': connection_frequency,
                'unique_destinations': unique_destinations,
                'total_connections': len(recent_connections)
            }
            
        except Exception as e:
            self.logger.error(f"流量模式分析失败: {e}")
            return {'pattern_type': 'error', 'error': str(e)}


class CodeStructureAnalyzer(LoggerMixin):
    """代码结构分析器"""
    
    def __init__(self):
        """初始化代码结构分析器"""
        self.suspicious_api_patterns = {
            'crypto_mining': [r'crypto.*mine', r'hash.*rate', r'mining.*pool'],
            'data_theft': [r'contact.*export', r'sms.*export', r'location.*track'],
            'remote_control': [r'remote.*shell', r'backdoor.*access', r'command.*control'],
            'system_manipulation': [r'root.*access', r'su.*command', r'system.*modify']
        }
        
        self.obfuscation_indicators = [
            r'[a-zA-Z]{1}[0-9]+[a-zA-Z]+',  # 随机变量名
            r'\\x[0-9a-fA-F]{2}',  # 十六进制编码  
            r'base64',  # Base64编码
            r'eval\(',  # 动态执行
        ]
    
    def analyze_file_structure(self, file_path: str, file_content: bytes) -> CodeStructureInfo:
        """分析文件结构"""
        try:
            info = CodeStructureInfo(
                file_path=file_path,
                file_type=self._detect_file_type(file_path, file_content),
                size=len(file_content),
                entropy=self._calculate_entropy(file_content)
            )
            
            # 转换为文本进行分析
            try:
                text_content = file_content.decode('utf-8', errors='ignore')
            except:
                text_content = str(file_content)
            
            # 提取各种信息
            info.api_calls = self._extract_api_calls(text_content)
            info.strings = self._extract_strings(text_content)
            info.imports = self._extract_imports(text_content)
            info.obfuscation_indicators = self._detect_obfuscation(text_content)
            
            return info
            
        except Exception as e:
            self.logger.error(f"文件结构分析失败 {file_path}: {e}")
            return CodeStructureInfo(
                file_path=file_path,
                file_type='unknown',
                size=len(file_content),
                entropy=0.0
            )
    
    def _detect_file_type(self, file_path: str, content: bytes) -> str:
        """检测文件类型"""
        if file_path.endswith('.dex'):
            return 'dex'
        elif file_path.endswith('.so'):
            return 'native_library'
        elif file_path.endswith('.xml'):
            return 'xml'
        elif content.startswith(b'dex\n'):
            return 'dex'
        elif content.startswith(b'\x7fELF'):
            return 'elf'
        return 'unknown'
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算文件熵值"""
        if not data:
            return 0.0
        
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequency:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _extract_api_calls(self, content: str) -> List[str]:
        """提取API调用"""
        api_calls = []
        
        # Java方法调用模式
        java_api_pattern = r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        api_calls.extend(re.findall(java_api_pattern, content))
        
        # Android API模式
        android_api_pattern = r'android\.([a-zA-Z_][a-zA-Z0-9_\.]*)'
        api_calls.extend(re.findall(android_api_pattern, content))
        
        return list(set(api_calls))[:100]
    
    def _extract_strings(self, content: str) -> List[str]:
        """提取字符串常量"""
        string_pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
        strings = re.findall(string_pattern, content)
        
        filtered_strings = []
        for s in strings:
            if isinstance(s, tuple):
                s = s[0]
            if 3 <= len(s) <= 100:
                filtered_strings.append(s)
        
        return filtered_strings[:50]
    
    def _extract_imports(self, content: str) -> List[str]:
        """提取导入语句"""
        imports = []
        
        import_pattern = r'import\s+([a-zA-Z_][a-zA-Z0-9_\.]*);'
        imports.extend(re.findall(import_pattern, content))
        
        return list(set(imports))
    
    def _detect_obfuscation(self, content: str) -> List[str]:
        """检测代码混淆"""
        indicators = []
        
        for pattern in self.obfuscation_indicators:
            if re.search(pattern, content):
                indicators.append(f"检测到混淆模式: {pattern}")
        
        return indicators
    
    def analyze_suspicious_patterns(self, code_info: CodeStructureInfo) -> List[SecurityIndicator]:
        """分析可疑模式"""
        indicators = []
        
        try:
            # 分析API调用模式
            for pattern_type, patterns in self.suspicious_api_patterns.items():
                matched_apis = []
                
                for api in code_info.api_calls:
                    for pattern in patterns:
                        if re.search(pattern, api, re.IGNORECASE):
                            matched_apis.append(api)
                
                if matched_apis:
                    severity = Severity.HIGH if len(matched_apis) > 2 else Severity.MEDIUM
                    indicators.append(SecurityIndicator(
                        indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                        severity=severity,
                        confidence=0.7,
                        description=f"检测到{pattern_type}相关API调用",
                        evidence={'pattern_type': pattern_type, 'matched_apis': matched_apis}
                    ))
            
            # 分析文件熵值
            if code_info.entropy > 7.5:
                indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=f"文件熵值异常高: {code_info.entropy:.2f}",
                    evidence={'entropy': code_info.entropy}
                ))
            
            # 分析混淆指标
            if code_info.obfuscation_indicators:
                indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    description=f"检测到代码混淆: {len(code_info.obfuscation_indicators)}个指标",
                    evidence={'obfuscation_indicators': code_info.obfuscation_indicators}
                ))
            
        except Exception as e:
            self.logger.error(f"可疑模式分析失败: {e}")
        
        return indicators


class IntegratedBehaviorAnalyzer(LoggerMixin):
    """集成行为分析器"""
    
    def __init__(self):
        """初始化集成行为分析器"""
        self.network_monitor = NetworkBehaviorMonitor()
        self.code_analyzer = CodeStructureAnalyzer()
        
    def comprehensive_behavior_analysis(self, 
                                      network_data: Optional[Dict[str, Any]] = None,
                                      code_files: Optional[List[Dict[str, bytes]]] = None) -> Dict[str, Any]:
        """综合行为分析"""
        try:
            analysis_result = {
                'network_analysis': {},
                'code_analysis': {},
                'integrated_risk_score': 0.0,
                'comprehensive_indicators': [],
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            network_risk = 0.0
            code_risk = 0.0
            
            # 网络行为分析
            if network_data:
                traffic_pattern = self.network_monitor.analyze_traffic_pattern()
                network_risk = traffic_pattern.get('risk_score', 0.0)
                analysis_result['network_analysis'] = traffic_pattern
            
            # 代码结构分析
            if code_files:
                code_results = []
                total_code_risk = 0.0
                
                for file_info in code_files[:10]:
                    file_path = file_info.get('path', 'unknown')
                    file_content = file_info.get('content', b'')
                    
                    code_info = self.code_analyzer.analyze_file_structure(file_path, file_content)
                    indicators = self.code_analyzer.analyze_suspicious_patterns(code_info)
                    
                    file_risk = len(indicators) * 0.2
                    code_results.append({
                        'file_path': file_path,
                        'risk_score': min(file_risk, 1.0),
                        'indicators': len(indicators)
                    })
                    total_code_risk += file_risk
                
                if code_results:
                    code_risk = min(total_code_risk / len(code_results), 1.0)
                    analysis_result['code_analysis'] = {
                        'files_analyzed': len(code_results),
                        'average_risk_score': code_risk,
                        'file_reports': code_results
                    }
            
            # 计算综合风险评分
            if network_data and code_files:
                analysis_result['integrated_risk_score'] = (network_risk * 0.4 + code_risk * 0.6)
            elif network_data:
                analysis_result['integrated_risk_score'] = network_risk
            elif code_files:
                analysis_result['integrated_risk_score'] = code_risk
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"综合行为分析失败: {e}")
            return {
                'integrated_risk_score': 0.0,
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def start_continuous_monitoring(self):
        """启动持续监控"""
        self.network_monitor.start_monitoring()
        self.logger.info("集成行为分析器：持续监控已启动")
    
    def stop_continuous_monitoring(self):
        """停止持续监控"""
        self.network_monitor.stop_monitoring()
        self.logger.info("集成行为分析器：持续监控已停止")