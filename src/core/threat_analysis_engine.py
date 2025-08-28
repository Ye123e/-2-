#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁分析引擎 - 智能威胁评估系统
"""

import json
import time
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from ..utils.logger import LoggerMixin
from .virus_scan_engine import ThreatDetection, ThreatLevel


class ThreatCategory(Enum):
    MALWARE = "MALWARE"
    SPYWARE = "SPYWARE" 
    TROJAN = "TROJAN"
    PRIVACY_RISK = "PRIVACY_RISK"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(Enum):
    QUARANTINE = "QUARANTINE"
    REMOVE = "REMOVE"
    MONITOR = "MONITOR"


@dataclass
class SecurityIndicator:
    indicator_type: str
    severity: Severity
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MitigationAction:
    action_type: ActionType
    description: str
    estimated_time: int
    requires_user_consent: bool = False


@dataclass
class ThreatAssessment:
    app_package: str
    risk_score: float
    threat_level: ThreatLevel
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    indicators: List[SecurityIndicator] = field(default_factory=list)
    mitigation_actions: List[MitigationAction] = field(default_factory=list)
    assessment_time: datetime = field(default_factory=datetime.now)


class RiskCalculator(LoggerMixin):
    """多维度风险评分计算器"""
    
    def __init__(self):
        self.weights = {
            'permission': 0.4,   # 权限风险 40%
            'behavior': 0.3,     # 行为风险 30%
            'signature': 0.2,    # 特征匹配 20%
            'environment': 0.1   # 环境风险 10%
        }
        
        self.dangerous_permissions = {
            'SEND_SMS': 0.9, 'READ_SMS': 0.8, 'READ_CONTACTS': 0.7,
            'RECORD_AUDIO': 0.8, 'DEVICE_ADMIN': 1.0, 'INTERNET': 0.3
        }
    
    def calculate_permission_risk(self, permissions: List[str]) -> Tuple[float, List[SecurityIndicator]]:
        """计算权限风险评分"""
        if not permissions:
            return 0.0, []
        
        indicators = []
        score = 0.0
        count = 0
        
        for permission in permissions:
            clean_perm = permission.replace('android.permission.', '')
            if clean_perm in self.dangerous_permissions:
                risk_weight = self.dangerous_permissions[clean_perm]
                score += risk_weight
                count += 1
                
                if risk_weight >= 0.7:
                    indicators.append(SecurityIndicator(
                        indicator_type="PERMISSION_ABUSE",
                        severity=Severity.HIGH if risk_weight >= 0.8 else Severity.MEDIUM,
                        confidence=0.9,
                        description=f"高风险权限: {clean_perm}",
                        evidence={'permission': clean_perm}
                    ))
        
        final_score = score / count if count > 0 else 0.0
        return min(final_score, 1.0), indicators
    
    def calculate_behavior_risk(self, behavior_data: Dict[str, Any]) -> Tuple[float, List[SecurityIndicator]]:
        """计算行为风险评分"""
        # 简化的行为分析
        score = 0.0
        indicators = []
        
        network_connections = behavior_data.get('network_connections', [])
        if len(network_connections) > 10:  # 过多网络连接
            score += 0.3
            indicators.append(SecurityIndicator(
                indicator_type="NETWORK_ANOMALY",
                severity=Severity.MEDIUM,
                confidence=0.7,
                description="网络连接异常",
                evidence={'connection_count': len(network_connections)}
            ))
        
        return min(score, 1.0), indicators
    
    def calculate_signature_risk(self, detections: List[ThreatDetection]) -> Tuple[float, List[SecurityIndicator]]:
        """计算特征匹配风险评分"""
        if not detections:
            return 0.0, []
        
        max_risk = 0.0
        indicators = []
        
        for detection in detections:
            risk_value = self._threat_level_to_score(detection.threat_level)
            risk_value *= detection.confidence
            max_risk = max(max_risk, risk_value)
            
            indicators.append(SecurityIndicator(
                indicator_type="FILE_SIGNATURE",
                severity=self._threat_level_to_severity(detection.threat_level),
                confidence=detection.confidence,
                description=f"特征匹配: {detection.threat_name}",
                evidence={'detection_id': detection.threat_id}
            ))
        
        return max_risk, indicators
    
    def calculate_environment_risk(self, app_info: Dict[str, Any]) -> Tuple[float, List[SecurityIndicator]]:
        """计算环境风险评分"""
        score = 0.0
        indicators = []
        
        # 检查安装来源
        install_source = app_info.get('install_source', '')
        if install_source and not self._is_trusted_source(install_source):
            score += 0.4
            indicators.append(SecurityIndicator(
                indicator_type="UNTRUSTED_SOURCE",
                severity=Severity.MEDIUM,
                confidence=0.7,
                description=f"来自不可信源: {install_source}",
                evidence={'install_source': install_source}
            ))
        
        return min(score, 1.0), indicators
    
    def calculate_overall_risk(self, permissions: List[str], behavior_data: Dict[str, Any],
                              detections: List[ThreatDetection], app_info: Dict[str, Any]) -> Tuple[float, List[SecurityIndicator]]:
        """计算综合风险评分"""
        
        perm_score, perm_indicators = self.calculate_permission_risk(permissions)
        behavior_score, behavior_indicators = self.calculate_behavior_risk(behavior_data)
        signature_score, signature_indicators = self.calculate_signature_risk(detections)
        env_score, env_indicators = self.calculate_environment_risk(app_info)
        
        final_score = (
            perm_score * self.weights['permission'] +
            behavior_score * self.weights['behavior'] +
            signature_score * self.weights['signature'] +
            env_score * self.weights['environment']
        )
        
        all_indicators = perm_indicators + behavior_indicators + signature_indicators + env_indicators
        
        return final_score, all_indicators
    
    def _threat_level_to_score(self, threat_level: ThreatLevel) -> float:
        mapping = {
            ThreatLevel.CLEAN: 0.0, ThreatLevel.LOW: 0.2, ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.8, ThreatLevel.CRITICAL: 1.0
        }
        return mapping.get(threat_level, 0.0)
    
    def _threat_level_to_severity(self, threat_level: ThreatLevel) -> Severity:
        mapping = {
            ThreatLevel.LOW: Severity.LOW, ThreatLevel.MEDIUM: Severity.MEDIUM,
            ThreatLevel.HIGH: Severity.HIGH, ThreatLevel.CRITICAL: Severity.CRITICAL
        }
        return mapping.get(threat_level, Severity.LOW)
    
    def _is_trusted_source(self, source: str) -> bool:
        trusted = ['com.android.vending', 'com.sec.android.app.samsungapps']
        return source in trusted


class ThreatAnalysisEngine(LoggerMixin):
    """威胁分析引擎主类"""
    
    def __init__(self):
        self.risk_calculator = RiskCalculator()
        self.analysis_stats = {'total_analyzed': 0, 'high_risk_count': 0}
    
    def analyze_threat(self, app_info: Dict[str, Any], 
                      detections: List[ThreatDetection] = None,
                      behavior_data: Dict[str, Any] = None) -> ThreatAssessment:
        """威胁分析主方法"""
        
        if detections is None:
            detections = []
        if behavior_data is None:
            behavior_data = {}
        
        package_name = app_info.get('package_name', '')
        permissions = app_info.get('permissions', [])
        
        # 计算风险评分
        risk_score, indicators = self.risk_calculator.calculate_overall_risk(
            permissions, behavior_data, detections, app_info
        )
        
        # 确定威胁级别
        threat_level = self._score_to_threat_level(risk_score)
        
        # 威胁分类
        threat_categories = self._classify_threats(indicators, detections)
        
        # 生成缓解措施
        mitigation_actions = self._generate_mitigation_actions(threat_level, threat_categories)
        
        assessment = ThreatAssessment(
            app_package=package_name,
            risk_score=risk_score,
            threat_level=threat_level,
            threat_categories=threat_categories,
            indicators=indicators,
            mitigation_actions=mitigation_actions
        )
        
        self._update_stats(assessment)
        self.logger.info(f"威胁分析完成: {package_name}, 评分: {risk_score:.3f}")
        
        return assessment
    
    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """风险评分转威胁级别"""
        if score >= 0.8: return ThreatLevel.CRITICAL
        elif score >= 0.6: return ThreatLevel.HIGH
        elif score >= 0.4: return ThreatLevel.MEDIUM
        elif score >= 0.2: return ThreatLevel.LOW
        else: return ThreatLevel.CLEAN
    
    def _classify_threats(self, indicators: List[SecurityIndicator], 
                         detections: List[ThreatDetection]) -> List[ThreatCategory]:
        """威胁分类"""
        categories = set()
        
        # 基于检测结果分类
        for detection in detections:
            if 'trojan' in detection.threat_name.lower():
                categories.add(ThreatCategory.TROJAN)
            elif 'spy' in detection.threat_name.lower():
                categories.add(ThreatCategory.SPYWARE)
            else:
                categories.add(ThreatCategory.MALWARE)
        
        # 基于指标分类
        for indicator in indicators:
            if indicator.indicator_type == "PERMISSION_ABUSE":
                categories.add(ThreatCategory.PRIVACY_RISK)
        
        return list(categories)
    
    def _generate_mitigation_actions(self, threat_level: ThreatLevel,
                                   categories: List[ThreatCategory]) -> List[MitigationAction]:
        """生成缓解措施"""
        actions = []
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append(MitigationAction(
                action_type=ActionType.QUARANTINE,
                description="立即隔离可疑应用",
                estimated_time=1,
                requires_user_consent=True
            ))
            
            if threat_level == ThreatLevel.CRITICAL:
                actions.append(MitigationAction(
                    action_type=ActionType.REMOVE,
                    description="删除恶意应用",
                    estimated_time=2,
                    requires_user_consent=True
                ))
        elif threat_level == ThreatLevel.MEDIUM:
            actions.append(MitigationAction(
                action_type=ActionType.MONITOR,
                description="加强监控应用行为",
                estimated_time=0,
                requires_user_consent=False
            ))
        
        return actions
    
    def _update_stats(self, assessment: ThreatAssessment):
        """更新统计信息"""
        self.analysis_stats['total_analyzed'] += 1
        if assessment.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.analysis_stats['high_risk_count'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取分析统计"""
        return self.analysis_stats.copy()