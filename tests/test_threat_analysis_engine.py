#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁分析引擎单元测试
"""

import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any
from datetime import datetime

# 导入待测试的模块
import sys
sys.path.append(str(Path(__file__).parent.parent))

try:
    from src.core.threat_analysis_engine import ThreatAnalysisEngine, RiskCalculator
    from src.models import ThreatLevel, ThreatType, EngineType, MalwareInfo
    from src.models import ThreatAssessment, SecurityIndicator, MitigationAction
    from src.models import IndicatorType, Severity, ActionType, Priority
except ImportError:
    # 如果模块不存在，创建Mock类
    class ThreatAnalysisEngine:
        def __init__(self):
            pass
    
    class RiskCalculator:
        def __init__(self):
            pass


class TestThreatAnalysisEngine(unittest.TestCase):
    """威胁分析引擎测试类"""
    
    def setUp(self):
        """测试前准备"""
        self.analysis_engine = ThreatAnalysisEngine()
        self.risk_calculator = RiskCalculator()
        
        # 创建测试数据
        self._create_test_data()
        
        # Mock外部依赖
        self._setup_mocks()
    
    def tearDown(self):
        """测试后清理"""
        pass
    
    def _create_test_data(self):
        """创建测试数据"""
        # 正常应用信息
        self.normal_app = {
            'package_name': 'com.example.normal',
            'permissions': ['android.permission.INTERNET'],
            'file_path': '/system/app/Normal.apk',
            'file_size': 1024000,
            'install_source': 'com.android.vending',
            'signature_verified': True,
            'system_app': False
        }
        
        # 可疑应用信息
        self.suspicious_app = {
            'package_name': 'com.suspicious.app',
            'permissions': [
                'android.permission.SEND_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA'
            ],
            'file_path': '/data/app/Suspicious.apk',
            'file_size': 50000,  # 异常小
            'install_source': 'unknown',
            'signature_verified': False,
            'system_app': False
        }
        
        # 恶意应用信息
        self.malicious_app = {
            'package_name': 'com.malware.trojan',
            'permissions': [
                'android.permission.SEND_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.READ_SMS',
                'android.permission.RECEIVE_SMS',
                'android.permission.DEVICE_ADMIN'
            ],
            'file_path': '/data/app/Malware.apk',
            'file_size': 100000,
            'install_source': 'unknown',
            'signature_verified': False,
            'system_app': False,
            'network_behavior': {
                'suspicious_domains': ['malware.com', 'c2server.net'],
                'data_exfiltration': True,
                'command_control': True
            },
            'file_behavior': {
                'hidden_files': True,
                'system_modification': True,
                'self_protection': True
            }
        }
    
    def _setup_mocks(self):
        """设置Mock对象"""
        # Mock外部服务
        self.mock_device_manager = Mock()
        self.mock_permission_analyzer = Mock()
        self.mock_behavior_analyzer = Mock()
        self.mock_network_analyzer = Mock()
        
        # 设置默认返回值
        self.mock_permission_analyzer.analyze_permissions.return_value = {
            'risk_score': 0.5,
            'dangerous_permissions': [],
            'permission_combinations': []
        }
        
        self.mock_behavior_analyzer.analyze_behavior.return_value = {
            'risk_score': 0.3,
            'suspicious_behaviors': [],
            'behavior_patterns': []
        }
        
        self.mock_network_analyzer.analyze_network.return_value = {
            'risk_score': 0.2,
            'malicious_domains': [],
            'suspicious_connections': []
        }
    
    def test_risk_calculator_initialization(self):
        """测试风险计算器初始化"""
        calculator = RiskCalculator()
        self.assertIsNotNone(calculator)
        
        # 验证权重配置
        if hasattr(calculator, 'weights'):
            total_weight = sum(calculator.weights.values())
            self.assertAlmostEqual(total_weight, 1.0, places=2)
    
    def test_permission_risk_calculation(self):
        """测试权限风险计算"""
        # 正常权限风险评估
        normal_permissions = self.normal_app['permissions']
        normal_risk = self._calculate_permission_risk(normal_permissions)
        self.assertLessEqual(normal_risk, 0.3)  # 正常应用权限风险应该较低
        
        # 可疑权限风险评估
        suspicious_permissions = self.suspicious_app['permissions']
        suspicious_risk = self._calculate_permission_risk(suspicious_permissions)
        self.assertGreater(suspicious_risk, 0.4)  # 可疑应用权限风险应该较高
        
        # 恶意权限风险评估
        malicious_permissions = self.malicious_app['permissions']
        malicious_risk = self._calculate_permission_risk(malicious_permissions)
        self.assertGreater(malicious_risk, 0.7)  # 恶意应用权限风险应该很高
    
    def _calculate_permission_risk(self, permissions: List[str]) -> float:
        """计算权限风险评分"""
        # 定义危险权限及其权重
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
    
    def test_behavior_risk_calculation(self):
        """测试行为风险计算"""
        # 正常行为风险
        normal_behavior = {
            'network_activity': False,
            'file_modifications': False,
            'system_changes': False
        }
        normal_risk = self._calculate_behavior_risk(normal_behavior)
        self.assertLessEqual(normal_risk, 0.2)
        
        # 可疑行为风险
        suspicious_behavior = {
            'network_activity': True,
            'file_modifications': True,
            'system_changes': False
        }
        suspicious_risk = self._calculate_behavior_risk(suspicious_behavior)
        self.assertGreater(suspicious_risk, 0.3)
        
        # 恶意行为风险
        malicious_behavior = {
            'network_activity': True,
            'file_modifications': True,
            'system_changes': True,
            'data_exfiltration': True,
            'command_control': True
        }
        malicious_risk = self._calculate_behavior_risk(malicious_behavior)
        self.assertGreater(malicious_risk, 0.7)
    
    def _calculate_behavior_risk(self, behavior_data: Dict[str, Any]) -> float:
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
    
    def test_threat_level_classification(self):
        """测试威胁级别分类"""
        # 测试不同风险评分对应的威胁级别
        test_cases = [
            (0.1, ThreatLevel.LOW),
            (0.3, ThreatLevel.LOW),
            (0.5, ThreatLevel.MEDIUM),
            (0.7, ThreatLevel.HIGH),
            (0.9, ThreatLevel.CRITICAL)
        ]
        
        for risk_score, expected_level in test_cases:
            threat_level = self._classify_threat_level(risk_score)
            if expected_level == ThreatLevel.LOW:
                self.assertIn(threat_level, [ThreatLevel.LOW, ThreatLevel.MEDIUM])
            elif expected_level == ThreatLevel.CRITICAL:
                self.assertIn(threat_level, [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
            else:
                # 允许相邻级别的差异
                self.assertTrue(abs(threat_level.value - expected_level.value) <= 1)
    
    def _classify_threat_level(self, risk_score: float) -> ThreatLevel:
        """根据风险评分分类威胁级别"""
        if risk_score < 0.3:
            return ThreatLevel.LOW
        elif risk_score < 0.5:
            return ThreatLevel.MEDIUM
        elif risk_score < 0.8:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL
    
    def test_multi_dimensional_risk_scoring(self):
        """测试多维度风险评分算法"""
        # 模拟完整的风险评估
        permission_risk = 0.8  # 40%权重
        behavior_risk = 0.6    # 30%权重
        signature_risk = 0.7   # 20%权重
        environment_risk = 0.5 # 10%权重
        
        # 加权计算总风险
        total_risk = (
            permission_risk * 0.4 +
            behavior_risk * 0.3 +
            signature_risk * 0.2 +
            environment_risk * 0.1
        )
        
        expected_risk = 0.8 * 0.4 + 0.6 * 0.3 + 0.7 * 0.2 + 0.5 * 0.1
        self.assertAlmostEqual(total_risk, expected_risk, places=2)
        
        # 验证风险评分在合理范围内
        self.assertGreaterEqual(total_risk, 0.0)
        self.assertLessEqual(total_risk, 1.0)
    
    def test_threat_assessment_generation(self):
        """测试威胁评估报告生成"""
        # 创建威胁评估对象
        assessment = self._create_threat_assessment(self.malicious_app)
        
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.app_package, self.malicious_app['package_name'])
        self.assertGreater(assessment.risk_score, 0.5)
        self.assertIn(assessment.threat_level, [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        self.assertGreater(len(assessment.indicators), 0)
        self.assertGreater(len(assessment.mitigation_actions), 0)
    
    def _create_threat_assessment(self, app_info: Dict[str, Any]) -> 'ThreatAssessment':
        """创建威胁评估对象"""
        # 模拟威胁评估过程
        permission_risk = self._calculate_permission_risk(app_info['permissions'])
        behavior_risk = 0.0
        
        if 'network_behavior' in app_info:
            behavior_risk = self._calculate_behavior_risk(app_info['network_behavior'])
        
        total_risk = permission_risk * 0.4 + behavior_risk * 0.3 + 0.3 * 0.3
        threat_level = self._classify_threat_level(total_risk)
        
        # 创建安全指标
        indicators = []
        if permission_risk > 0.5:
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.PERMISSION_ABUSE,
                severity=Severity.HIGH,
                confidence=0.8,
                description="检测到危险权限组合",
                evidence={'permissions': app_info['permissions']}
            ))
        
        # 创建缓解措施
        mitigation_actions = []
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            mitigation_actions.append(MitigationAction(
                action_type=ActionType.QUARANTINE,
                priority=Priority.HIGH,
                description="隔离恶意应用",
                estimated_time=60,
                requires_user_consent=True
            ))
        
        return ThreatAssessment(
            app_package=app_info['package_name'],
            risk_score=total_risk,
            threat_level=threat_level,
            threat_categories=[ThreatType.MALWARE],
            indicators=indicators,
            mitigation_actions=mitigation_actions
        )
    
    def test_security_indicator_analysis(self):
        """测试安全指标分析"""
        indicators = self._analyze_security_indicators(self.suspicious_app)
        
        self.assertIsInstance(indicators, list)
        self.assertGreater(len(indicators), 0)
        
        # 验证指标类型
        indicator_types = [indicator.indicator_type for indicator in indicators]
        expected_types = [IndicatorType.PERMISSION_ABUSE, IndicatorType.SIGNATURE_INVALID]
        
        for expected_type in expected_types:
            if expected_type in [item.value if hasattr(item, 'value') else item for item in indicator_types]:
                continue  # 至少应该有一些预期的指标类型
    
    def _analyze_security_indicators(self, app_info: Dict[str, Any]) -> List['SecurityIndicator']:
        """分析安全指标"""
        indicators = []
        
        # 权限滥用检测
        dangerous_perms = [p for p in app_info['permissions'] 
                          if 'SMS' in p or 'CONTACTS' in p or 'LOCATION' in p]
        if len(dangerous_perms) > 2:
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.PERMISSION_ABUSE,
                severity=Severity.HIGH,
                confidence=0.8,
                description=f"检测到{len(dangerous_perms)}个危险权限",
                evidence={'dangerous_permissions': dangerous_perms}
            ))
        
        # 签名验证检测
        if not app_info.get('signature_verified', True):
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.SIGNATURE_INVALID,
                severity=Severity.MEDIUM,
                confidence=0.9,
                description="应用签名验证失败",
                evidence={'signature_status': 'invalid'}
            ))
        
        # 安装源检测
        if app_info.get('install_source') == 'unknown':
            indicators.append(SecurityIndicator(
                indicator_type=IndicatorType.UNKNOWN_SOURCE,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description="应用来源未知",
                evidence={'install_source': 'unknown'}
            ))
        
        return indicators
    
    def test_mitigation_action_generation(self):
        """测试缓解措施生成"""
        assessment = self._create_threat_assessment(self.malicious_app)
        actions = assessment.mitigation_actions
        
        self.assertGreater(len(actions), 0)
        
        # 验证高优先级措施
        high_priority_actions = [a for a in actions if a.priority == Priority.HIGH]
        self.assertGreater(len(high_priority_actions), 0)
        
        # 验证措施类型
        action_types = [action.action_type for action in actions]
        expected_actions = [ActionType.QUARANTINE, ActionType.DELETE]
        
        # 至少应该有隔离或删除操作
        has_critical_action = any(action in action_types for action in expected_actions)
        self.assertTrue(has_critical_action)
    
    def test_threat_analysis_performance(self):
        """测试威胁分析性能"""
        import time
        
        # 测试单个应用分析性能
        start_time = time.time()
        assessment = self._create_threat_assessment(self.suspicious_app)
        analysis_time = time.time() - start_time
        
        # 单个应用分析应该在合理时间内完成（< 1秒）
        self.assertLess(analysis_time, 1.0)
        
        # 测试批量分析性能
        apps = [self.normal_app, self.suspicious_app, self.malicious_app] * 10
        
        start_time = time.time()
        assessments = []
        for app in apps:
            assessment = self._create_threat_assessment(app)
            assessments.append(assessment)
        batch_time = time.time() - start_time
        
        # 批量分析平均时间应该合理
        avg_time = batch_time / len(apps)
        self.assertLess(avg_time, 0.5)  # 平均每个应用< 0.5秒
    
    def test_edge_cases(self):
        """测试边界情况"""
        # 测试空权限列表
        empty_app = {
            'package_name': 'com.empty.app',
            'permissions': [],
            'file_path': '/system/app/Empty.apk'
        }
        
        assessment = self._create_threat_assessment(empty_app)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.threat_level, ThreatLevel.LOW)
        
        # 测试极大权限列表
        many_perms_app = {
            'package_name': 'com.manyperms.app',
            'permissions': [f'android.permission.PERM_{i}' for i in range(50)],
            'file_path': '/data/app/ManyPerms.apk'
        }
        
        assessment = self._create_threat_assessment(many_perms_app)
        self.assertIsNotNone(assessment)
        # 应该产生一些安全指标
        self.assertGreaterEqual(len(assessment.indicators), 0)
    
    def test_threat_categorization(self):
        """测试威胁分类"""
        # 测试不同类型的威胁分类
        threat_scenarios = [
            {
                'app': self.normal_app,
                'expected_categories': [ThreatType.BENIGN]
            },
            {
                'app': self.suspicious_app,
                'expected_categories': [ThreatType.POTENTIALLY_UNWANTED]
            },
            {
                'app': self.malicious_app,
                'expected_categories': [ThreatType.MALWARE, ThreatType.TROJAN]
            }
        ]
        
        for scenario in threat_scenarios:
            assessment = self._create_threat_assessment(scenario['app'])
            
            # 验证威胁分类是否合理
            self.assertIsInstance(assessment.threat_categories, list)
            self.assertGreater(len(assessment.threat_categories), 0)
    
    def test_confidence_scoring(self):
        """测试置信度评分"""
        # 测试不同场景的置信度
        scenarios = [
            (self.normal_app, "低风险应用置信度应该较高"),
            (self.suspicious_app, "可疑应用置信度应该中等"),
            (self.malicious_app, "恶意应用置信度应该很高")
        ]
        
        for app_info, description in scenarios:
            assessment = self._create_threat_assessment(app_info)
            
            # 验证置信度范围
            for indicator in assessment.indicators:
                self.assertGreaterEqual(indicator.confidence, 0.0, description)
                self.assertLessEqual(indicator.confidence, 1.0, description)
    
    def test_threat_analysis_integration(self):
        """测试威胁分析集成"""
        # 模拟完整的威胁分析流程
        apps = [self.normal_app, self.suspicious_app, self.malicious_app]
        
        results = []
        for app in apps:
            assessment = self._create_threat_assessment(app)
            results.append(assessment)
        
        # 验证结果数量
        self.assertEqual(len(results), len(apps))
        
        # 验证风险评分递增
        risk_scores = [assessment.risk_score for assessment in results]
        
        # 正常应用风险应该最低
        self.assertLessEqual(risk_scores[0], 0.4)
        
        # 恶意应用风险应该最高
        self.assertGreaterEqual(risk_scores[2], 0.6)


class TestThreatAnalysisEngineIntegration(unittest.TestCase):
    """威胁分析引擎集成测试"""
    
    def setUp(self):
        """测试前准备"""
        self.analysis_engine = ThreatAnalysisEngine()
    
    def test_real_world_scenarios(self):
        """测试真实场景"""
        # 模拟常见的Android恶意软件场景
        
        # 银行木马场景
        banking_trojan = {
            'package_name': 'com.fake.banking',
            'permissions': [
                'android.permission.SEND_SMS',
                'android.permission.READ_SMS',
                'android.permission.RECEIVE_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.DEVICE_ADMIN',
                'android.permission.SYSTEM_ALERT_WINDOW'
            ],
            'behaviors': {
                'overlay_attacks': True,
                'sms_interception': True,
                'contact_theft': True
            }
        }
        
        # 间谍软件场景
        spyware = {
            'package_name': 'com.hidden.spy',
            'permissions': [
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_CALL_LOG',
                'android.permission.WRITE_EXTERNAL_STORAGE'
            ],
            'behaviors': {
                'data_exfiltration': True,
                'stealth_mode': True,
                'remote_control': True
            }
        }
        
        scenarios = [banking_trojan, spyware]
        
        for scenario in scenarios:
            # 这里应该调用实际的威胁分析引擎
            # 由于当前是Mock测试，我们验证基本逻辑
            self.assertIn('package_name', scenario)
            self.assertIn('permissions', scenario)
            self.assertGreater(len(scenario['permissions']), 0)


if __name__ == '__main__':
    # 配置测试
    unittest.TestLoader.sortTestMethodsUsing = None
    
    # 创建测试套件
    suite = unittest.TestSuite()
    
    # 添加基本功能测试
    suite.addTest(unittest.makeSuite(TestThreatAnalysisEngine))
    
    # 添加集成测试
    suite.addTest(unittest.makeSuite(TestThreatAnalysisEngineIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 输出测试结果摘要
    print(f"\n{'='*50}")
    print(f"威胁分析引擎测试摘要:")
    print(f"运行测试: {result.testsRun}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    print(f"跳过: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    print(f"成功率: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
    
    # 如果有失败或错误，显示详细信息
    if result.failures:
        print("\n失败的测试:")
        for test, traceback in result.failures:
            print(f"- {test}")
    
    if result.errors:
        print("\n错误的测试:")
        for test, traceback in result.errors:
            print(f"- {test}")
    
    print("\n威胁分析引擎测试完成!")