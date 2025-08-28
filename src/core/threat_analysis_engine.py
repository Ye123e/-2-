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
        
        # 检测危险权限组合
        dangerous_perms = [p for p in permissions 
                          if any(danger in p for danger in ['SMS', 'CONTACTS', 'LOCATION', 'RECORD_AUDIO', 'CAMERA'])]
        
        if len(dangerous_perms) > 2:
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.PERMISSION_ABUSE,
                severity=Severity.HIGH,
                confidence=0.8,
                description=f"检测到{len(dangerous_perms)}个危险权限",
                evidence={'dangerous_permissions': dangerous_perms}
            ))
        
        return indicators
    
    def analyze_app_info(self, app_info: Dict[str, Any]) -> ThreatAssessment:
        """分析应用信息并生成威胁评估"""
        try:
            # 计算各项风险评分
            permission_risk = self.risk_calculator.calculate_permission_risk(
                app_info.get('permissions', [])
            )
            
            behavior_risk = 0.0
            if 'network_behavior' in app_info:
                behavior_risk = self.risk_calculator.calculate_behavior_risk(
                    app_info['network_behavior']
                )
            
            # 签名验证风险
            signature_risk = 0.0 if app_info.get('signature_verified', True) else 0.7
            
            # 环境风险（安装源等）
            environment_risk = 0.3 if app_info.get('install_source') == 'unknown' else 0.0
            
            # 计算总体风险
            total_risk = self.risk_calculator.calculate_total_risk(
                permission_risk, behavior_risk, signature_risk, environment_risk
            )
            
            # 分类威胁级别
            threat_level = self.classify_threat_level(total_risk)
            
            # 生成安全指标
            indicators = self.analyze_permissions(app_info.get('permissions', []))
            
            # 添加签名验证指标
            if not app_info.get('signature_verified', True):
                indicators.append(SecurityIndicator(
                    indicator_type=IndicatorType.SIGNATURE_INVALID,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    description="应用签名验证失败",
                    evidence={'signature_verified': False}
                ))
            
            # 生成缓解措施建议
            mitigation_actions = self._generate_mitigation_actions(threat_level, indicators)
            
            # 创建威胁评估对象
            assessment = ThreatAssessment(
                app_package=app_info.get('package_name', 'unknown'),
                risk_score=total_risk,
                threat_level=threat_level,
                indicators=indicators,
                mitigation_actions=mitigation_actions,
                confidence=0.8,
                details={
                    'permission_risk': permission_risk,
                    'behavior_risk': behavior_risk,
                    'signature_risk': signature_risk,
                    'environment_risk': environment_risk
                }
            )
            
            self.logger.info(f"威胁分析完成: {app_info.get('package_name')} - 威胁级别: {threat_level.value}")
            return assessment
            
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