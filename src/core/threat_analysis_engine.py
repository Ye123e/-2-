#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁分析引擎
负责Android应用的威胁分析和风险评估
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..models import (
    ThreatLevel, ThreatType, EngineType, MalwareInfo,
    ThreatAssessment, SecurityIndicator, MitigationAction,
    IndicatorType, Severity, ActionType, Priority
)


class RiskCalculator:
    """风险计算器"""
    
    def __init__(self):
        """初始化风险计算器"""
        self.weights = {
            'permission_risk': 0.4,
            'behavior_risk': 0.3,
            'signature_risk': 0.2,
            'environment_risk': 0.1
        }
        self.logger = logging.getLogger(__name__)
    
    def calculate_permission_risk(self, permissions: List[str]) -> float:
        """计算权限风险评分"""
        dangerous_permissions = {
            'android.permission.SEND_SMS': 0.8,
            'android.permission.READ_CONTACTS': 0.6,
            'android.permission.ACCESS_FINE_LOCATION': 0.7,
            'android.permission.RECORD_AUDIO': 0.7,
            'android.permission.CAMERA': 0.6,
            'android.permission.READ_SMS': 0.8,
            'android.permission.RECEIVE_SMS': 0.7,
            'android.permission.DEVICE_ADMIN': 0.9,
            'android.permission.WRITE_EXTERNAL_STORAGE': 0.4
        }
        
        risk_score = 0.0
        permission_count = len(permissions)
        
        for permission in permissions:
            if permission in dangerous_permissions:
                risk_score += dangerous_permissions[permission]
        
        # 权限数量加权
        if permission_count > 5:
            risk_score += 0.2
        if permission_count > 10:
            risk_score += 0.3
        
        # 归一化到0-1范围
        return min(risk_score / max(len(dangerous_permissions), permission_count), 1.0)
    
    def calculate_behavior_risk(self, behavior_data: Dict[str, Any]) -> float:
        """计算行为风险评分"""
        risk_factors = {
            'network_activity': 0.2,
            'file_modifications': 0.3,
            'system_changes': 0.4,
            'data_exfiltration': 0.8,
            'command_control': 0.9,
            'self_protection': 0.7,
            'rootkit_behavior': 0.9
        }
        
        risk_score = 0.0
        for factor, weight in risk_factors.items():
            if behavior_data.get(factor, False):
                risk_score += weight
        
        return min(risk_score, 1.0)
    
    def calculate_total_risk(self, 
                           permission_risk: float, 
                           behavior_risk: float,
                           signature_risk: float = 0.0,
                           environment_risk: float = 0.0) -> float:
        """计算总体风险评分"""
        total_risk = (
            permission_risk * self.weights['permission_risk'] +
            behavior_risk * self.weights['behavior_risk'] +
            signature_risk * self.weights['signature_risk'] +
            environment_risk * self.weights['environment_risk']
        )
        return min(total_risk, 1.0)


class ThreatAnalysisEngine:
    """威胁分析引擎"""
    
    def __init__(self):
        """初始化威胁分析引擎"""
        self.logger = logging.getLogger(__name__)
        self.risk_calculator = RiskCalculator()
        
        # 初始化增强型分析器
        self.permission_analyzer = AdvancedPermissionAnalyzer()
        self.behavior_analyzer = BehaviorPatternAnalyzer()
        self.network_analyzer = NetworkBehaviorAnalyzer()
        self.code_analyzer = CodeStructureAnalyzer()
        
    def classify_threat_level(self, risk_score: float) -> ThreatLevel:
        """根据风险评分分类威胁级别"""
        if risk_score < 0.3:
            return ThreatLevel.LOW
        elif risk_score < 0.5:
            return ThreatLevel.MEDIUM
        elif risk_score < 0.8:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL
    
    def analyze_permissions(self, permissions: List[str]) -> List[SecurityIndicator]:
        """分析权限安全指标"""
        indicators = []
        
        # 使用高级权限分析器
        permission_analysis = self.permission_analyzer.analyze_permission_risk(permissions)
        
        # 根据权限分析结果生成安全指标
        if permission_analysis['total_risk_score'] > 0.7:
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.PERMISSION_ABUSE,
                severity=Severity.HIGH,
                confidence=0.9,
                description=f"检测到高风险权限组合，风险评分: {permission_analysis['total_risk_score']:.2f}",
                evidence={
                    'permission_analysis': permission_analysis,
                    'detected_patterns': permission_analysis.get('detected_patterns', [])
                }
            ))
        
        # 检查危险权限模式
        for pattern in permission_analysis.get('detected_patterns', []):
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                severity=Severity.HIGH,
                confidence=0.8,
                description=f"检测到{pattern['pattern']}: {pattern['description']}",
                evidence={'pattern': pattern}
            ))
        
        return indicators
    
    def analyze_app_behavior(self, behavior_data: Dict[str, Any]) -> List[SecurityIndicator]:
        """分析应用行为模式"""
        indicators = []
        
        # 使用行为模式分析器
        behavior_analysis = self.behavior_analyzer.analyze_behavior_patterns(behavior_data)
        
        # 根据行为分析结果生成指标
        for pattern in behavior_analysis.get('detected_patterns', []):
            severity = Severity.HIGH if pattern['risk_contribution'] > 0.7 else Severity.MEDIUM
            
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                severity=severity,
                confidence=behavior_analysis.get('confidence_score', 0.5),
                description=f"检测到可疑行为模式: {pattern['description']}",
                evidence={
                    'behavior_pattern': pattern,
                    'matched_indicators': pattern.get('matched_indicators', [])
                }
            ))
        
        # 分析网络行为
        if 'network_connections' in behavior_data:
            network_risk, network_reasons = self.network_analyzer.analyze_network_connections(
                behavior_data['network_connections']
            )
            
            if network_risk > 0.5:
                indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.NETWORK_ANOMALY,
                    severity=Severity.HIGH if network_risk > 0.7 else Severity.MEDIUM,
                    confidence=0.8,
                    description=f"检测到可疑网络行为，风险评分: {network_risk:.2f}",
                    evidence={'network_reasons': network_reasons}
                ))
        
        # 分析代码结构
        if 'api_calls' in behavior_data:
            code_risk, code_reasons = self.code_analyzer.analyze_api_calls(
                behavior_data['api_calls']
            )
            
            if code_risk > 0.5:
                indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    description=f"检测到可疑API调用模式，风险评分: {code_risk:.2f}",
                    evidence={'code_reasons': code_reasons}
                ))
        
        return indicators
    
    def comprehensive_threat_analysis(self, app_info: Dict[str, Any]) -> ThreatAssessment:
        """
        综合威胁分析
        
        Args:
            app_info: 应用信息，包含权限、行为数据等
            
        Returns:
            综合威胁评估报告
        """
        try:
            # 初始化评估结果
            assessment = ThreatAssessment(
                app_package=app_info.get('package_name', 'unknown'),
                risk_score=0.0,
                threat_level=ThreatLevel.LOW,
                confidence=0.0
            )
            
            all_indicators = []
            risk_components = {}
            
            # 1. 权限风险分析
            permissions = app_info.get('permissions', [])
            if permissions:
                permission_indicators = self.analyze_permissions(permissions)
                all_indicators.extend(permission_indicators)
                
                permission_analysis = self.permission_analyzer.analyze_permission_risk(permissions)
                risk_components['permission_risk'] = permission_analysis['total_risk_score']
            
            # 2. 行为模式分析
            behavior_data = app_info.get('behavior_data', {})
            if behavior_data:
                behavior_indicators = self.analyze_app_behavior(behavior_data)
                all_indicators.extend(behavior_indicators)
                
                behavior_analysis = self.behavior_analyzer.analyze_behavior_patterns(behavior_data)
                risk_components['behavior_risk'] = behavior_analysis['overall_risk_score']
            
            # 3. 签名验证分析
            signature_verified = app_info.get('signature_verified', True)
            if not signature_verified:
                all_indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.SIGNATURE_INVALID,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    description="应用签名验证失败",
                    evidence={'signature_verified': False}
                ))
                risk_components['signature_risk'] = 0.7
            else:
                risk_components['signature_risk'] = 0.0
            
            # 4. 环境风险分析
            install_source = app_info.get('install_source')
            if install_source == 'unknown' or install_source not in ['play_store', 'official']:
                all_indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.UNKNOWN_SOURCE,
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    description=f"应用来源不明: {install_source}",
                    evidence={'install_source': install_source}
                ))
                risk_components['environment_risk'] = 0.4
            else:
                risk_components['environment_risk'] = 0.0
            
            # 5. 计算综合风险评分
            total_risk = self._calculate_comprehensive_risk(risk_components)
            assessment.risk_score = total_risk
            assessment.threat_level = self.classify_threat_level(total_risk)
            
            # 6. 计算置信度
            assessment.confidence = self._calculate_assessment_confidence(
                app_info, all_indicators, risk_components
            )
            
            # 7. 设置指标和缓解措施
            assessment.indicators = all_indicators
            assessment.mitigation_actions = self._generate_comprehensive_mitigation_actions(
                assessment.threat_level, all_indicators
            )
            
            # 8. 设置详细信息
            assessment.details = {
                'risk_components': risk_components,
                'total_indicators': len(all_indicators),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            if permissions:
                assessment.details['permission_analysis'] = self.permission_analyzer.analyze_permission_risk(permissions)
            
            if behavior_data:
                assessment.details['behavior_analysis'] = self.behavior_analyzer.analyze_behavior_patterns(behavior_data)
            
            self.logger.info(
                f"综合威胁分析完成: {app_info.get('package_name')} - "
                f"威胁级别: {assessment.threat_level.value}, "
                f"风险评分: {assessment.risk_score:.2f}, "
                f"置信度: {assessment.confidence:.2f}"
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"综合威胁分析失败: {e}")
            # 返回默认的高风险评估
            return ThreatAssessment(
                app_package=app_info.get('package_name', 'unknown'),
                risk_score=0.8,
                threat_level=ThreatLevel.HIGH,
                confidence=0.3,
                details={'error': str(e)}
            )
    
    def _calculate_comprehensive_risk(self, risk_components: Dict[str, float]) -> float:
        """计算综合风险评分"""
        # 权重配置
        weights = {
            'permission_risk': 0.35,
            'behavior_risk': 0.35,
            'signature_risk': 0.20,
            'environment_risk': 0.10
        }
        
        total_risk = 0.0
        for component, risk_value in risk_components.items():
            weight = weights.get(component, 0.0)
            total_risk += risk_value * weight
        
        return min(total_risk, 1.0)
    
    def _calculate_assessment_confidence(self, app_info: Dict[str, Any], 
                                       indicators: List[SecurityIndicator],
                                       risk_components: Dict[str, float]) -> float:
        """计算评估置信度"""
        # 数据完整性评分
        data_completeness = 0.0
        max_completeness = 4  # 权限、行为、签名、环境
        
        if app_info.get('permissions'):
            data_completeness += 1
        if app_info.get('behavior_data'):
            data_completeness += 1
        if 'signature_verified' in app_info:
            data_completeness += 1
        if 'install_source' in app_info:
            data_completeness += 1
        
        completeness_score = data_completeness / max_completeness
        
        # 指标一致性评分
        if indicators:
            avg_indicator_confidence = sum(ind.confidence for ind in indicators) / len(indicators)
        else:
            avg_indicator_confidence = 0.5
        
        # 风险组件一致性
        risk_consistency = 1.0
        if len(risk_components) > 1:
            risk_values = list(risk_components.values())
            risk_variance = sum((r - sum(risk_values)/len(risk_values))**2 for r in risk_values) / len(risk_values)
            risk_consistency = max(0.5, 1.0 - risk_variance)
        
        # 综合置信度
        confidence = (completeness_score * 0.4 + 
                     avg_indicator_confidence * 0.4 + 
                     risk_consistency * 0.2)
        
        return min(confidence, 1.0)
    
    def _generate_comprehensive_mitigation_actions(self, threat_level: ThreatLevel, 
                                                 indicators: List[SecurityIndicator]) -> List[MitigationAction]:
        """生成综合缓解措施建议"""
        actions = []
        
        # 根据威胁级别生成基础建议
        if threat_level == ThreatLevel.CRITICAL:
            actions.extend([
                MitigationAction(ActionType.DELETE, Priority.URGENT, "立即卸载该应用"),
                MitigationAction(ActionType.QUARANTINE, Priority.URGENT, "隔离相关文件"),
                MitigationAction(ActionType.ALERT, Priority.HIGH, "通知用户安全威胁"),
                MitigationAction(ActionType.MONITOR, Priority.HIGH, "监控设备安全状态")
            ])
        elif threat_level == ThreatLevel.HIGH:
            actions.extend([
                MitigationAction(ActionType.QUARANTINE, Priority.HIGH, "隔离可疑应用"),
                MitigationAction(ActionType.MONITOR, Priority.MEDIUM, "加强监控频率"),
                MitigationAction(ActionType.BLOCK, Priority.MEDIUM, "限制网络访问")
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            actions.extend([
                MitigationAction(ActionType.MONITOR, Priority.MEDIUM, "定期监控应用行为"),
                MitigationAction(ActionType.ALERT, Priority.LOW, "提醒用户注意权限使用")
            ])
        
        # 根据具体指标生成针对性建议
        for indicator in indicators:
            if indicator.indicator_type == IndicatorType.PERMISSION_ABUSE:
                actions.append(MitigationAction(
                    ActionType.DISABLE, Priority.MEDIUM, 
                    "禁用过度权限或限制权限使用"
                ))
            elif indicator.indicator_type == IndicatorType.NETWORK_ANOMALY:
                actions.append(MitigationAction(
                    ActionType.BLOCK, Priority.HIGH,
                    "阻断可疑网络连接"
                ))
            elif indicator.indicator_type == IndicatorType.SIGNATURE_INVALID:
                actions.append(MitigationAction(
                    ActionType.ALERT, Priority.HIGH,
                    "验证应用来源和签名"
                ))
        
        return actions
    
    def analyze_app_info(self, app_info: Dict[str, Any]) -> ThreatAssessment:
        """
        分析应用信息并生成威胁评估（兼容性方法）
        
        这个方法保持与API的兼容性，内部使用新的综合分析功能
        """
        try:
            # 使用新的综合分析功能
            return self.comprehensive_threat_analysis(app_info)
            
        except Exception as e:
            self.logger.error(f"威胁分析过程中发生错误: {str(e)}")
            # 返回默认的高风险评估
            return ThreatAssessment(
                app_package=app_info.get('package_name', 'unknown'),
                risk_score=0.8,
                threat_level=ThreatLevel.HIGH,
                confidence=0.5,
                details={'error': str(e)}
            )
    
    def _generate_mitigation_actions(self, threat_level: ThreatLevel, indicators: List[SecurityIndicator]) -> List[MitigationAction]:
        """生成缓解措施建议"""
        actions = []
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append(MitigationAction(
                action_type=ActionType.QUARANTINE,
                priority=Priority.HIGH,
                description="建议隔离或卸载此应用"
            ))
        
        # 根据具体指标生成针对性建议
        for indicator in indicators:
            if indicator.indicator_type == IndicatorType.PERMISSION_ABUSE:
                actions.append(MitigationAction(
                    action_type=ActionType.MONITOR,
                    priority=Priority.MEDIUM,
                    description="监控应用权限使用情况"
                ))
            elif indicator.indicator_type == IndicatorType.SIGNATURE_INVALID:
                actions.append(MitigationAction(
                    action_type=ActionType.ALERT,
                    priority=Priority.HIGH,
                    description="发出签名异常警告"
                ))
        
        return actions


class NetworkBehaviorAnalyzer:
    """网络行为分析器"""
    
    def __init__(self):
        self.suspicious_domains = [
            'malware-c2.com', 'evil-server.net', 'trojan-control.org',
            'phishing-site.com', 'fake-bank.net'
        ]
        self.suspicious_ips = ['192.168.1.100', '10.0.0.50']
    
    def analyze_network_connections(self, connections: List[Dict[str, Any]]) -> tuple[float, List[str]]:
        """分析网络连接"""
        risk_score = 0.0
        risk_reasons = []
        
        for conn in connections:
            remote_addr = conn.get('remote_address', '')
            remote_port = conn.get('remote_port', 0)
            
            # 检查可疑域名
            if any(domain in remote_addr for domain in self.suspicious_domains):
                risk_score = max(risk_score, 0.9)
                risk_reasons.append(f"连接到可疑域名: {remote_addr}")
            
            # 检查可疑端口
            suspicious_ports = [1234, 4444, 5555, 6666, 31337]
            if remote_port in suspicious_ports:
                risk_score = max(risk_score, 0.6)
                risk_reasons.append(f"使用可疑端口: {remote_port}")
        
        return risk_score, risk_reasons


class AdvancedPermissionAnalyzer(LoggerMixin):
    """高级权限分析器"""
    
    def __init__(self):
        """初始化高级权限分析器"""
        # 权限危险等级定义
        self.permission_risks = {
            # 高危险权限
            'android.permission.SEND_SMS': {'risk': 0.9, 'category': '短信控制'},
            'android.permission.CALL_PHONE': {'risk': 0.8, 'category': '通话控制'},
            'android.permission.RECORD_AUDIO': {'risk': 0.8, 'category': '音频监听'},
            'android.permission.CAMERA': {'risk': 0.7, 'category': '相机控制'},
            'android.permission.ACCESS_FINE_LOCATION': {'risk': 0.8, 'category': '位置跟踪'},
            'android.permission.READ_CONTACTS': {'risk': 0.7, 'category': '联系人访问'},
            'android.permission.READ_SMS': {'risk': 0.8, 'category': '短信读取'},
            'android.permission.RECEIVE_SMS': {'risk': 0.7, 'category': '短信接收'},
            'android.permission.DEVICE_ADMIN': {'risk': 0.9, 'category': '设备管理'},
            'android.permission.SYSTEM_ALERT_WINDOW': {'risk': 0.6, 'category': '系统覆盖'},
            
            # 中危险权限
            'android.permission.WRITE_EXTERNAL_STORAGE': {'risk': 0.4, 'category': '文件写入'},
            'android.permission.READ_EXTERNAL_STORAGE': {'risk': 0.3, 'category': '文件读取'},
            'android.permission.INTERNET': {'risk': 0.3, 'category': '网络访问'},
            'android.permission.ACCESS_NETWORK_STATE': {'risk': 0.2, 'category': '网络状态'},
            'android.permission.WAKE_LOCK': {'risk': 0.3, 'category': '睡眠控制'},
            'android.permission.VIBRATE': {'risk': 0.1, 'category': '振动控制'},
            
            # 特殊权限
            'android.permission.WRITE_SETTINGS': {'risk': 0.6, 'category': '设置修改'},
            'android.permission.INSTALL_PACKAGES': {'risk': 0.9, 'category': '应用安装'},
            'android.permission.DELETE_PACKAGES': {'risk': 0.9, 'category': '应用卸载'},
            'android.permission.CHANGE_WIFI_STATE': {'risk': 0.4, 'category': 'WiFi控制'}
        }
        
        # 危险权限组合模式
        self.dangerous_permission_patterns = {
            '银行木马模式': {
                'permissions': ['SYSTEM_ALERT_WINDOW', 'CALL_PHONE', 'SEND_SMS'],
                'risk_multiplier': 1.5,
                'description': '具备银行木马特征的权限组合'
            },
            '间谍软件模式': {
                'permissions': ['RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'CAMERA', 'READ_SMS'],
                'risk_multiplier': 1.4,
                'description': '具备间谍软件特征的权限组合'
            },
            '数据窃取模式': {
                'permissions': ['READ_CONTACTS', 'READ_SMS', 'ACCESS_FINE_LOCATION', 'INTERNET'],
                'risk_multiplier': 1.3,
                'description': '具备数据窃取特征的权限组合'
            },
            '远程控制模式': {
                'permissions': ['DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW', 'INTERNET'],
                'risk_multiplier': 1.6,
                'description': '具备远程控制特征的权限组合'
            }
        }
    
    def analyze_permission_risk(self, permissions: List[str]) -> Dict[str, Any]:
        """分析权限风险"""
        try:
            analysis_result = {
                'total_risk_score': 0.0,
                'permission_breakdown': {},
                'detected_patterns': [],
                'risk_categories': {},
                'recommendations': []
            }
            
            # 分析单个权限风险
            for permission in permissions:
                if permission in self.permission_risks:
                    perm_info = self.permission_risks[permission]
                    analysis_result['permission_breakdown'][permission] = perm_info
                    
                    # 按类别统计风险
                    category = perm_info['category']
                    if category not in analysis_result['risk_categories']:
                        analysis_result['risk_categories'][category] = {
                            'permissions': [],
                            'total_risk': 0.0
                        }
                    
                    analysis_result['risk_categories'][category]['permissions'].append(permission)
                    analysis_result['risk_categories'][category]['total_risk'] += perm_info['risk']
            
            # 计算总体风险评分
            base_risk = sum(info['risk'] for info in analysis_result['permission_breakdown'].values())
            analysis_result['total_risk_score'] = min(base_risk / len(permissions) if permissions else 0, 1.0)
            
            # 检测危险权限模式
            for pattern_name, pattern_info in self.dangerous_permission_patterns.items():
                pattern_perms = set(pattern_info['permissions'])
                user_perms = set(perm.split('.')[-1] for perm in permissions)
                
                if pattern_perms.issubset(user_perms):
                    analysis_result['detected_patterns'].append({
                        'pattern': pattern_name,
                        'description': pattern_info['description'],
                        'risk_multiplier': pattern_info['risk_multiplier']
                    })
                    
                    # 应用风险倍数
                    analysis_result['total_risk_score'] *= pattern_info['risk_multiplier']
            
            # 统一风险评分到 0-1 范围
            analysis_result['total_risk_score'] = min(analysis_result['total_risk_score'], 1.0)
            
            # 生成建议
            self._generate_permission_recommendations(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"权限风险分析失败: {e}")
            return {'total_risk_score': 0.0, 'error': str(e)}
    
    def _generate_permission_recommendations(self, analysis_result: Dict[str, Any]):
        """生成权限建议"""
        recommendations = []
        
        # 根据风险等级给出建议
        risk_score = analysis_result['total_risk_score']
        
        if risk_score >= 0.8:
            recommendations.append('高风险应用，建议立即卸载')
        elif risk_score >= 0.6:
            recommendations.append('中高风险应用，建议密切监控')
        elif risk_score >= 0.4:
            recommendations.append('中等风险应用，建议定期检查')
        
        # 针对特定模式的建议
        for pattern in analysis_result['detected_patterns']:
            recommendations.append(f'检测到{pattern["pattern"]}，{pattern["description"]}')
        
        # 针对高风险权限类别的建议
        for category, info in analysis_result['risk_categories'].items():
            if info['total_risk'] > 1.5:
                recommendations.append(f'该应用请求过多{category}相关权限，需要谨慎对待')
        
        analysis_result['recommendations'] = recommendations


class BehaviorPatternAnalyzer(LoggerMixin):
    """行为模式分析器"""
    
    def __init__(self):
        """初始化行为模式分析器"""
        # 可疑行为模式定义
        self.behavior_patterns = {
            'stealth_operation': {
                'indicators': [
                    'hide_app_icon', 'no_main_activity', 'minimal_ui',
                    'background_only', 'transparent_activity'
                ],
                'risk_weight': 0.7,
                'description': '隐蔽操作模式'
            },
            'data_exfiltration': {
                'indicators': [
                    'compress_data', 'encrypt_transmission', 'scheduled_upload',
                    'batch_data_collection', 'external_server_communication'
                ],
                'risk_weight': 0.8,
                'description': '数据外泄模式'
            },
            'system_manipulation': {
                'indicators': [
                    'modify_system_settings', 'install_other_apps', 'root_access_attempt',
                    'disable_security_apps', 'change_device_admin'
                ],
                'risk_weight': 0.9,
                'description': '系统操控模式'
            },
            'surveillance': {
                'indicators': [
                    'continuous_location_tracking', 'periodic_audio_recording',
                    'screenshot_capture', 'keylogger_behavior', 'call_monitoring'
                ],
                'risk_weight': 0.8,
                'description': '监控行为模式'
            },
            'financial_fraud': {
                'indicators': [
                    'intercept_sms_otp', 'overlay_banking_apps', 'steal_payment_info',
                    'unauthorized_transactions', 'fake_payment_interface'
                ],
                'risk_weight': 0.9,
                'description': '金融欺诈模式'
            }
        }
        
        # 行为时间模式
        self.temporal_patterns = {
            'night_activity': {'weight': 0.3, 'description': '夜间异常活动'},
            'periodic_execution': {'weight': 0.4, 'description': '定时执行模式'},
            'burst_activity': {'weight': 0.5, 'description': '突发性高频活动'}
        }
    
    def analyze_behavior_patterns(self, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析应用行为模式
        
        Args:
            behavior_data: 行为数据，包含各种行为指标
            
        Returns:
            行为分析结果
        """
        try:
            analysis_result = {
                'overall_risk_score': 0.0,
                'detected_patterns': [],
                'temporal_analysis': {},
                'behavior_indicators': {},
                'risk_breakdown': {},
                'confidence_score': 0.0
            }
            
            # 分析行为模式
            for pattern_name, pattern_info in self.behavior_patterns.items():
                pattern_risk = self._analyze_single_pattern(
                    behavior_data, pattern_info['indicators'], pattern_info['risk_weight']
                )
                
                if pattern_risk['match_score'] > 0.3:  # 阈值设定
                    analysis_result['detected_patterns'].append({
                        'pattern': pattern_name,
                        'description': pattern_info['description'],
                        'match_score': pattern_risk['match_score'],
                        'risk_contribution': pattern_risk['risk_contribution'],
                        'matched_indicators': pattern_risk['matched_indicators']
                    })
                    
                    analysis_result['overall_risk_score'] += pattern_risk['risk_contribution']
            
            # 分析时间模式
            temporal_risk = self._analyze_temporal_patterns(behavior_data)
            analysis_result['temporal_analysis'] = temporal_risk
            analysis_result['overall_risk_score'] += temporal_risk.get('risk_contribution', 0.0)
            
            # 统一风险评分
            analysis_result['overall_risk_score'] = min(analysis_result['overall_risk_score'], 1.0)
            
            # 计算置信度
            analysis_result['confidence_score'] = self._calculate_confidence(
                behavior_data, analysis_result['detected_patterns']
            )
            
            # 生成风险分解
            analysis_result['risk_breakdown'] = self._generate_risk_breakdown(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"行为模式分析失败: {e}")
            return {'overall_risk_score': 0.0, 'error': str(e)}
    
    def _analyze_single_pattern(self, behavior_data: Dict[str, Any], 
                              indicators: List[str], risk_weight: float) -> Dict[str, Any]:
        """分析单个行为模式"""
        matched_indicators = []
        total_indicators = len(indicators)
        
        for indicator in indicators:
            if behavior_data.get(indicator, False):
                matched_indicators.append(indicator)
        
        match_score = len(matched_indicators) / total_indicators if total_indicators > 0 else 0
        risk_contribution = match_score * risk_weight
        
        return {
            'match_score': match_score,
            'risk_contribution': risk_contribution,
            'matched_indicators': matched_indicators
        }
    
    def _analyze_temporal_patterns(self, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析时间模式"""
        temporal_analysis = {
            'detected_patterns': [],
            'risk_contribution': 0.0
        }
        
        activity_times = behavior_data.get('activity_timestamps', [])
        if not activity_times:
            return temporal_analysis
        
        # 简化的时间模式分析
        night_activities = sum(1 for t in activity_times if self._is_night_time(t))
        night_ratio = night_activities / len(activity_times) if activity_times else 0
        
        if night_ratio > 0.3:  # 30%以上的活动发生在夜间
            temporal_analysis['detected_patterns'].append('night_activity')
            temporal_analysis['risk_contribution'] += self.temporal_patterns['night_activity']['weight'] * night_ratio
        
        return temporal_analysis
    
    def _is_night_time(self, timestamp: str) -> bool:
        """判断是否为夜间时间"""
        try:
            # 简化实现，实际应该根据具体时间格式进行判断
            from datetime import datetime
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            return hour < 6 or hour > 22
        except:
            return False
    
    def _calculate_confidence(self, behavior_data: Dict[str, Any], 
                            detected_patterns: List[Dict[str, Any]]) -> float:
        """计算分析置信度"""
        # 基于数据质量和模式匹配数量计算置信度
        data_quality = min(len(behavior_data) / 10, 1.0)  # 数据丰富度
        pattern_strength = min(len(detected_patterns) / 3, 1.0)  # 模式匹配强度
        
        return (data_quality + pattern_strength) / 2
    
    def _generate_risk_breakdown(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """生成风险分解报告"""
        risk_breakdown = {
            'high_risk_patterns': [],
            'medium_risk_patterns': [],
            'low_risk_patterns': [],
            'recommendations': []
        }
        
        for pattern in analysis_result['detected_patterns']:
            risk_level = pattern['risk_contribution']
            pattern_info = {
                'pattern': pattern['pattern'],
                'description': pattern['description'],
                'risk_contribution': risk_level
            }
            
            if risk_level >= 0.7:
                risk_breakdown['high_risk_patterns'].append(pattern_info)
            elif risk_level >= 0.4:
                risk_breakdown['medium_risk_patterns'].append(pattern_info)
            else:
                risk_breakdown['low_risk_patterns'].append(pattern_info)
        
        # 生成建议
        if risk_breakdown['high_risk_patterns']:
            risk_breakdown['recommendations'].append('检测到高风险行为模式，建议立即采取行动')
        
        if analysis_result['overall_risk_score'] > 0.6:
            risk_breakdown['recommendations'].append('总体风险较高，建议进行深度安全检查')
        
        return risk_breakdown


class CodeStructureAnalyzer:
    """代码结构分析器"""
    
    def __init__(self):
        self.suspicious_api_patterns = {
            'crypto_mining': ['crypto', 'mining', 'hashrate'],
            'data_theft': ['contacts', 'sms', 'location', 'camera'],
            'remote_control': ['remote', 'control', 'backdoor'],
            'rootkit': ['root', 'su', 'system']
        }
    
    def analyze_api_calls(self, api_calls: List[str]) -> tuple[float, List[str]]:
        """分析API调用模式"""
        risk_score = 0.0
        risk_reasons = []
        
        api_text = ' '.join(api_calls).lower()
        
        for pattern_type, keywords in self.suspicious_api_patterns.items():
            matches = sum(1 for keyword in keywords if keyword in api_text)
            if matches >= 2:
                risk_score = max(risk_score, 0.6 + matches * 0.1)
                risk_reasons.append(f"检测到{pattern_type}相关API调用")
        
        return risk_score, risk_reasons