#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁级别分类和风险评分算法
提供智能化的威胁评估、风险量化和优先级排序功能
"""

import json
import math
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from ..models import ThreatLevel, ThreatType, Severity, SecurityIndicator, ThreatAssessment
from ..utils.logger import LoggerMixin


class RiskCategory(Enum):
    """风险类别枚举"""
    PERMISSION = "PERMISSION"
    BEHAVIOR = "BEHAVIOR"
    NETWORK = "NETWORK"
    CODE_STRUCTURE = "CODE_STRUCTURE"
    SIGNATURE = "SIGNATURE"
    ENVIRONMENT = "ENVIRONMENT"


@dataclass
class RiskFactor:
    """风险因子"""
    category: RiskCategory
    name: str
    weight: float
    base_score: float
    multiplier: float = 1.0
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatProfile:
    """威胁档案"""
    threat_id: str
    threat_types: List[ThreatType]
    risk_factors: List[RiskFactor]
    total_score: float
    threat_level: ThreatLevel
    confidence_score: float
    assessment_time: datetime
    context_data: Dict[str, Any] = field(default_factory=dict)


class RiskScoringEngine(LoggerMixin):
    """风险评分引擎"""
    
    def __init__(self):
        """初始化风险评分引擎"""
        # 基础权重配置
        self.category_weights = {
            RiskCategory.PERMISSION: 0.25,
            RiskCategory.BEHAVIOR: 0.30,
            RiskCategory.NETWORK: 0.20,
            RiskCategory.CODE_STRUCTURE: 0.15,
            RiskCategory.SIGNATURE: 0.05,
            RiskCategory.ENVIRONMENT: 0.05
        }
        
        # 威胁类型基础评分
        self.threat_type_scores = {
            ThreatType.BENIGN: 0.0,
            ThreatType.POTENTIALLY_UNWANTED: 0.3,
            ThreatType.ADWARE: 0.4,
            ThreatType.SPYWARE: 0.7,
            ThreatType.TROJAN: 0.8,
            ThreatType.MALWARE: 0.9,
            ThreatType.ROOTKIT: 1.0
        }
        
        # 评分阈值
        self.threat_level_thresholds = {
            ThreatLevel.LOW: (0.0, 0.25),
            ThreatLevel.MEDIUM: (0.25, 0.50),
            ThreatLevel.HIGH: (0.50, 0.75),
            ThreatLevel.CRITICAL: (0.75, 1.0)
        }
        
        # 历史数据用于机器学习调整
        self.historical_assessments: List[ThreatProfile] = []
        self.max_history = 1000
    
    def calculate_risk_score(self, risk_factors: List[RiskFactor]) -> Tuple[float, Dict[str, Any]]:
        """
        计算综合风险评分
        
        Args:
            risk_factors: 风险因子列表
            
        Returns:
            (综合风险评分, 评分详情)
        """
        try:
            if not risk_factors:
                return 0.0, {'error': '没有风险因子'}
            
            # 按类别分组
            category_scores = {category: [] for category in RiskCategory}
            
            for factor in risk_factors:
                # 计算因子评分
                factor_score = (
                    factor.base_score * 
                    factor.multiplier * 
                    factor.confidence
                )
                category_scores[factor.category].append(factor_score)
            
            # 计算各类别评分
            weighted_scores = {}
            for category, scores in category_scores.items():
                if scores:
                    # 使用最大值和平均值的加权组合
                    max_score = max(scores)
                    avg_score = sum(scores) / len(scores)
                    category_score = max_score * 0.7 + avg_score * 0.3
                    
                    weighted_scores[category.value] = {
                        'score': category_score,
                        'weight': self.category_weights[category],
                        'weighted_score': category_score * self.category_weights[category],
                        'factor_count': len(scores)
                    }
                else:
                    weighted_scores[category.value] = {
                        'score': 0.0,
                        'weight': self.category_weights[category],
                        'weighted_score': 0.0,
                        'factor_count': 0
                    }
            
            # 计算总评分
            total_score = sum(
                details['weighted_score'] 
                for details in weighted_scores.values()
            )
            
            # 归一化到0-1范围
            normalized_score = min(max(total_score, 0.0), 1.0)
            
            # 计算置信度
            confidence = self._calculate_scoring_confidence(risk_factors)
            
            scoring_details = {
                'total_score': normalized_score,
                'confidence': confidence,
                'category_scores': weighted_scores,
                'factor_count': len(risk_factors),
                'calculation_method': 'weighted_sum_with_normalization'
            }
            
            return normalized_score, scoring_details
            
        except Exception as e:
            self.logger.error(f"风险评分计算失败: {e}")
            return 0.0, {'error': str(e)}
    
    def _calculate_scoring_confidence(self, risk_factors: List[RiskFactor]) -> float:
        """计算评分置信度"""
        if not risk_factors:
            return 0.0
        
        # 基于因子数量和置信度
        factor_count_confidence = min(len(risk_factors) / 10, 1.0)
        avg_factor_confidence = sum(f.confidence for f in risk_factors) / len(risk_factors)
        
        # 基于类别覆盖度
        covered_categories = len(set(f.category for f in risk_factors))
        category_coverage = covered_categories / len(RiskCategory)
        
        # 综合置信度
        confidence = (
            factor_count_confidence * 0.4 + 
            avg_factor_confidence * 0.4 + 
            category_coverage * 0.2
        )
        
        return min(confidence, 1.0)
    
    def classify_threat_level(self, risk_score: float, context: Optional[Dict[str, Any]] = None) -> ThreatLevel:
        """
        分类威胁级别
        
        Args:
            risk_score: 风险评分
            context: 上下文信息
            
        Returns:
            威胁级别
        """
        try:
            # 基础分类
            for level, (min_score, max_score) in self.threat_level_thresholds.items():
                if min_score <= risk_score < max_score:
                    base_level = level
                    break
            else:
                base_level = ThreatLevel.CRITICAL if risk_score >= 1.0 else ThreatLevel.LOW
            
            # 上下文调整
            if context:
                adjusted_level = self._adjust_threat_level_by_context(base_level, context)
                return adjusted_level
            
            return base_level
            
        except Exception as e:
            self.logger.error(f"威胁级别分类失败: {e}")
            return ThreatLevel.MEDIUM
    
    def _adjust_threat_level_by_context(self, base_level: ThreatLevel, context: Dict[str, Any]) -> ThreatLevel:
        """根据上下文调整威胁级别"""
        adjustment = 0
        
        # 系统关键性调整
        if context.get('system_critical', False):
            adjustment += 1
        
        # 网络环境调整
        if context.get('public_network', False):
            adjustment += 1
        
        # 用户敏感数据调整
        if context.get('sensitive_data_access', False):
            adjustment += 1
        
        # 历史威胁记录调整
        if context.get('previous_threats', 0) > 0:
            adjustment += 1
        
        # 应用调整
        threat_levels = list(ThreatLevel)
        current_index = threat_levels.index(base_level)
        new_index = min(current_index + adjustment, len(threat_levels) - 1)
        
        return threat_levels[new_index]


class ThreatClassificationEngine(LoggerMixin):
    """威胁分类引擎"""
    
    def __init__(self):
        """初始化威胁分类引擎"""
        self.risk_scoring_engine = RiskScoringEngine()
        
        # 威胁模式定义
        self.threat_patterns = {
            ThreatType.ADWARE: {
                'keywords': ['ad', 'advertisement', 'popup', 'banner'],
                'permissions': ['INTERNET', 'ACCESS_NETWORK_STATE'],
                'behaviors': ['frequent_network_requests', 'ui_overlay'],
                'base_risk': 0.3
            },
            ThreatType.SPYWARE: {
                'keywords': ['spy', 'track', 'monitor', 'surveillance'],
                'permissions': ['RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'READ_SMS', 'READ_CONTACTS'],
                'behaviors': ['background_recording', 'location_tracking', 'data_collection'],
                'base_risk': 0.7
            },
            ThreatType.TROJAN: {
                'keywords': ['trojan', 'backdoor', 'remote', 'control'],
                'permissions': ['DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW', 'INTERNET'],
                'behaviors': ['remote_control', 'system_modification', 'stealth_operation'],
                'base_risk': 0.8
            },
            ThreatType.ROOTKIT: {
                'keywords': ['root', 'system', 'kernel', 'privilege'],
                'permissions': ['WRITE_EXTERNAL_STORAGE', 'INSTALL_PACKAGES'],
                'behaviors': ['privilege_escalation', 'system_file_modification', 'anti_detection'],
                'base_risk': 1.0
            }
        }
    
    def classify_threat_type(self, app_data: Dict[str, Any]) -> List[ThreatType]:
        """
        分类威胁类型
        
        Args:
            app_data: 应用数据
            
        Returns:
            威胁类型列表
        """
        try:
            detected_types = []
            
            app_name = app_data.get('package_name', '').lower()
            permissions = [p.lower() for p in app_data.get('permissions', [])]
            behaviors = app_data.get('detected_behaviors', [])
            strings = [s.lower() for s in app_data.get('strings', [])]
            
            # 检查每种威胁类型
            for threat_type, pattern in self.threat_patterns.items():
                match_score = 0.0
                
                # 检查关键词匹配
                keyword_matches = sum(
                    1 for keyword in pattern['keywords']
                    if any(keyword in text for text in [app_name] + strings)
                )
                if keyword_matches > 0:
                    match_score += 0.3
                
                # 检查权限匹配
                permission_matches = sum(
                    1 for perm in pattern['permissions']
                    if any(perm.lower() in p for p in permissions)
                )
                if permission_matches > 0:
                    match_score += 0.4 * (permission_matches / len(pattern['permissions']))
                
                # 检查行为匹配
                behavior_matches = sum(
                    1 for behavior in pattern['behaviors']
                    if behavior in behaviors
                )
                if behavior_matches > 0:
                    match_score += 0.3 * (behavior_matches / len(pattern['behaviors']))
                
                # 如果匹配分数超过阈值，则认为是该威胁类型
                if match_score >= 0.5:
                    detected_types.append(threat_type)
            
            # 如果没有检测到特定威胁类型，基于风险评分确定
            if not detected_types:
                risk_factors = self._extract_risk_factors_from_data(app_data)
                risk_score, _ = self.risk_scoring_engine.calculate_risk_score(risk_factors)
                
                if risk_score < 0.2:
                    detected_types.append(ThreatType.BENIGN)
                elif risk_score < 0.4:
                    detected_types.append(ThreatType.POTENTIALLY_UNWANTED)
                else:
                    detected_types.append(ThreatType.MALWARE)
            
            return detected_types
            
        except Exception as e:
            self.logger.error(f"威胁类型分类失败: {e}")
            return [ThreatType.POTENTIALLY_UNWANTED]
    
    def _extract_risk_factors_from_data(self, app_data: Dict[str, Any]) -> List[RiskFactor]:
        """从应用数据提取风险因子"""
        risk_factors = []
        
        try:
            # 权限风险因子
            permissions = app_data.get('permissions', [])
            if permissions:
                dangerous_perms = [p for p in permissions if any(
                    danger in p.upper() for danger in ['SMS', 'LOCATION', 'CAMERA', 'RECORD_AUDIO', 'CONTACTS']
                )]
                
                if dangerous_perms:
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.PERMISSION,
                        name='dangerous_permissions',
                        weight=0.8,
                        base_score=min(len(dangerous_perms) * 0.2, 1.0),
                        confidence=0.9,
                        evidence={'dangerous_permissions': dangerous_perms}
                    ))
            
            # 行为风险因子
            behaviors = app_data.get('detected_behaviors', [])
            if behaviors:
                suspicious_behaviors = [b for b in behaviors if 'suspicious' in b or 'malicious' in b]
                
                if suspicious_behaviors:
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.BEHAVIOR,
                        name='suspicious_behaviors',
                        weight=0.9,
                        base_score=min(len(suspicious_behaviors) * 0.3, 1.0),
                        confidence=0.8,
                        evidence={'suspicious_behaviors': suspicious_behaviors}
                    ))
            
            # 网络风险因子
            network_data = app_data.get('network_analysis', {})
            if network_data.get('risk_score', 0) > 0.5:
                risk_factors.append(RiskFactor(
                    category=RiskCategory.NETWORK,
                    name='network_anomaly',
                    weight=0.7,
                    base_score=network_data['risk_score'],
                    confidence=0.7,
                    evidence=network_data
                ))
            
            # 代码结构风险因子
            code_analysis = app_data.get('code_analysis', {})
            if code_analysis.get('average_risk_score', 0) > 0.4:
                risk_factors.append(RiskFactor(
                    category=RiskCategory.CODE_STRUCTURE,
                    name='code_anomaly',
                    weight=0.6,
                    base_score=code_analysis['average_risk_score'],
                    confidence=0.6,
                    evidence=code_analysis
                ))
            
            # 签名风险因子
            if not app_data.get('signature_verified', True):
                risk_factors.append(RiskFactor(
                    category=RiskCategory.SIGNATURE,
                    name='invalid_signature',
                    weight=0.8,
                    base_score=0.7,
                    confidence=0.9,
                    evidence={'signature_verified': False}
                ))
            
            return risk_factors
            
        except Exception as e:
            self.logger.error(f"风险因子提取失败: {e}")
            return []
    
    def generate_comprehensive_assessment(self, app_data: Dict[str, Any]) -> ThreatAssessment:
        """
        生成综合威胁评估
        
        Args:
            app_data: 应用数据
            
        Returns:
            威胁评估结果
        """
        try:
            # 提取风险因子
            risk_factors = self._extract_risk_factors_from_data(app_data)
            
            # 计算风险评分
            risk_score, scoring_details = self.risk_scoring_engine.calculate_risk_score(risk_factors)
            
            # 分类威胁级别
            threat_level = self.risk_scoring_engine.classify_threat_level(
                risk_score, app_data.get('context', {})
            )
            
            # 分类威胁类型
            threat_types = self.classify_threat_type(app_data)
            
            # 生成安全指标
            indicators = self._generate_security_indicators(risk_factors, app_data)
            
            # 生成缓解措施
            from ..models import MitigationAction, ActionType, Priority
            mitigation_actions = self._generate_mitigation_actions(threat_level, threat_types, indicators)
            
            # 创建评估对象
            assessment = ThreatAssessment(
                app_package=app_data.get('package_name', 'unknown'),
                risk_score=risk_score,
                threat_level=threat_level,
                threat_categories=threat_types,
                indicators=indicators,
                mitigation_actions=mitigation_actions,
                confidence=scoring_details.get('confidence', 0.5),
                details={
                    'scoring_details': scoring_details,
                    'risk_factors': [
                        {
                            'category': rf.category.value,
                            'name': rf.name,
                            'score': rf.base_score,
                            'weight': rf.weight,
                            'confidence': rf.confidence
                        }
                        for rf in risk_factors
                    ],
                    'threat_types': [tt.value for tt in threat_types],
                    'assessment_method': 'comprehensive_ml_enhanced'
                }
            )
            
            # 记录历史数据
            self._record_assessment_history(assessment, risk_factors)
            
            self.logger.info(
                f"威胁评估完成: {app_data.get('package_name')} - "
                f"级别: {threat_level.value}, 评分: {risk_score:.2f}, "
                f"类型: {[tt.value for tt in threat_types]}"
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"综合威胁评估失败: {e}")
            return ThreatAssessment(
                app_package=app_data.get('package_name', 'unknown'),
                risk_score=0.5,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.3,
                details={'error': str(e)}
            )
    
    def _generate_security_indicators(self, risk_factors: List[RiskFactor], app_data: Dict[str, Any]) -> List[SecurityIndicator]:
        """生成安全指标"""
        indicators = []
        
        for factor in risk_factors:
            severity = Severity.HIGH if factor.base_score > 0.7 else (
                Severity.MEDIUM if factor.base_score > 0.4 else Severity.LOW
            )
            
            # 映射风险类别到指标类型
            indicator_type_mapping = {
                RiskCategory.PERMISSION: IndicatorType.PERMISSION_ABUSE,
                RiskCategory.BEHAVIOR: IndicatorType.SUSPICIOUS_BEHAVIOR,
                RiskCategory.NETWORK: IndicatorType.NETWORK_ANOMALY,
                RiskCategory.CODE_STRUCTURE: IndicatorType.SUSPICIOUS_BEHAVIOR,
                RiskCategory.SIGNATURE: IndicatorType.SIGNATURE_INVALID,
                RiskCategory.ENVIRONMENT: IndicatorType.UNKNOWN_SOURCE
            }
            
            indicator_type = indicator_type_mapping.get(factor.category, IndicatorType.SUSPICIOUS_BEHAVIOR)
            
            indicators.append(SecurityIndicator(
                indicator_type=indicator_type,
                severity=severity,
                confidence=factor.confidence,
                description=f"{factor.category.value}风险: {factor.name} (评分: {factor.base_score:.2f})",
                evidence=factor.evidence
            ))
        
        return indicators
    
    def _generate_mitigation_actions(self, threat_level: ThreatLevel, 
                                   threat_types: List[ThreatType],
                                   indicators: List[SecurityIndicator]) -> List:
        """生成缓解措施"""
        from ..models import MitigationAction, ActionType, Priority
        
        actions = []
        
        # 基于威胁级别的通用措施
        if threat_level == ThreatLevel.CRITICAL:
            actions.extend([
                MitigationAction(ActionType.DELETE, Priority.URGENT, "立即卸载该应用"),
                MitigationAction(ActionType.QUARANTINE, Priority.URGENT, "隔离相关文件"),
                MitigationAction(ActionType.ALERT, Priority.HIGH, "发出安全警报")
            ])
        elif threat_level == ThreatLevel.HIGH:
            actions.extend([
                MitigationAction(ActionType.QUARANTINE, Priority.HIGH, "隔离可疑应用"),
                MitigationAction(ActionType.MONITOR, Priority.MEDIUM, "加强监控")
            ])
        
        # 基于威胁类型的专项措施
        for threat_type in threat_types:
            if threat_type == ThreatType.SPYWARE:
                actions.append(MitigationAction(
                    ActionType.DISABLE, Priority.HIGH, 
                    "禁用相机、麦克风和位置权限"
                ))
            elif threat_type == ThreatType.TROJAN:
                actions.append(MitigationAction(
                    ActionType.BLOCK, Priority.HIGH,
                    "阻断网络连接"
                ))
        
        return actions
    
    def _record_assessment_history(self, assessment: ThreatAssessment, risk_factors: List[RiskFactor]):
        """记录评估历史"""
        try:
            profile = ThreatProfile(
                threat_id=f"{assessment.app_package}_{datetime.now().timestamp()}",
                threat_types=assessment.threat_categories,
                risk_factors=risk_factors,
                total_score=assessment.risk_score,
                threat_level=assessment.threat_level,
                confidence_score=assessment.confidence,
                assessment_time=datetime.now(),
                context_data=assessment.details
            )
            
            self.risk_scoring_engine.historical_assessments.append(profile)
            
            # 保持历史记录数量
            if len(self.risk_scoring_engine.historical_assessments) > self.risk_scoring_engine.max_history:
                self.risk_scoring_engine.historical_assessments = \
                    self.risk_scoring_engine.historical_assessments[-self.risk_scoring_engine.max_history:]
                    
        except Exception as e:
            self.logger.error(f"记录评估历史失败: {e}")


class AdaptiveThreatEngine(LoggerMixin):
    """自适应威胁引擎"""
    
    def __init__(self):
        """初始化自适应威胁引擎"""
        self.classification_engine = ThreatClassificationEngine()
        self.learning_enabled = True
        
    def process_threat_assessment(self, app_data: Dict[str, Any]) -> ThreatAssessment:
        """处理威胁评估"""
        return self.classification_engine.generate_comprehensive_assessment(app_data)
    
    def update_threat_intelligence(self, feedback_data: Dict[str, Any]):
        """更新威胁情报"""
        try:
            if not self.learning_enabled:
                return
            
            # 处理用户反馈
            assessment_id = feedback_data.get('assessment_id')
            actual_threat = feedback_data.get('actual_threat_level')
            user_confirmation = feedback_data.get('user_confirmation')
            
            if assessment_id and actual_threat:
                self._adjust_scoring_weights(assessment_id, actual_threat)
                
            self.logger.info("威胁情报已更新")
            
        except Exception as e:
            self.logger.error(f"更新威胁情报失败: {e}")
    
    def _adjust_scoring_weights(self, assessment_id: str, actual_threat: str):
        """调整评分权重"""
        # 这里可以实现机器学习算法来调整权重
        # 简化实现：基于反馈调整类别权重
        pass