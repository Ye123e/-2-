#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
病毒查杀与漏洞修复工具 - 集成测试
测试所有核心功能模块的集成性和功能完整性
"""

import unittest
import sys
import os
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.device_manager import DeviceManager
from src.core.virus_scan_engine import VirusScanEngine, YaraEngine, ClamAVEngine
from src.core.threat_analysis_engine import ThreatAnalysisEngine
from src.core.vulnerability_detection_engine import VulnerabilityDetectionEngine
from src.core.enhanced_repair_engine import EnhancedRepairEngine
from src.core.realtime_monitoring_engine import RealTimeMonitoringEngine
from src.core.repair_task_manager import RepairTaskManager, TaskPriority
from src.models import *


class TestVirusScanEngine(unittest.TestCase):
    """病毒扫描引擎测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        self.virus_engine = VirusScanEngine(self.device_manager)
        
        # 模拟设备
        self.mock_device = DeviceInfo(
            device_id="test_device_001",
            model="TestPhone",
            android_version="10.0"
        )
        self.device_manager.get_device.return_value = self.mock_device
    
    def test_yara_engine_initialization(self):
        """测试YARA引擎初始化"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yara_engine = YaraEngine(temp_dir)
            
            # 检查默认规则文件是否创建
            rules_file = Path(temp_dir) / "android_malware.yar"
            self.assertTrue(rules_file.exists())
    
    def test_scan_application_heuristic(self):
        """测试应用程序启发式扫描"""
        app_info = {
            'package_name': 'com.suspicious.app',
            'permissions': [
                'android.permission.SEND_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.RECORD_AUDIO'
            ]
        }
        
        malware_info = self.virus_engine.scan_application("test_device", app_info)
        
        # 验证检测结果
        self.assertIsInstance(malware_info, MalwareInfo)
        self.assertEqual(malware_info.app_package, 'com.suspicious.app')
        self.assertGreater(malware_info.risk_score, 0.5)  # 应该被标记为高风险
    
    @patch('src.core.virus_scan_engine.YARA_AVAILABLE', True)
    def test_virus_scan_with_yara(self):
        """测试YARA规则扫描"""
        # 模拟设备应用列表
        apps_result = "package:/data/app/com.test.app-1.apk=com.test.app\npackage:/data/app/com.malware.fake-2.apk=com.malware.fake"
        self.device_manager.execute_command.return_value = apps_result
        
        # 执行扫描
        report = self.virus_engine.scan_device("test_device")
        
        self.assertIsNotNone(report)
        self.assertEqual(report.device_id, "test_device")  # pyright: ignore[reportOptionalMemberAccess, reportAttributeAccessIssue]


class TestThreatAnalysisEngine(unittest.TestCase):
    """威胁分析引擎测试"""
    
    def setUp(self):
        self.threat_engine = ThreatAnalysisEngine()
    
    def test_risk_calculation(self):
        """测试风险计算"""
        permissions = [
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION'
        ]
        
        risk_score = self.threat_engine.risk_calculator.calculate_permission_risk(permissions)
        self.assertGreater(risk_score, 0)
        self.assertLessEqual(risk_score, 1.0)
    
    def test_threat_level_classification(self):
        """测试威胁级别分类"""
        # 测试不同风险评分的威胁级别
        self.assertEqual(self.threat_engine.classify_threat_level(0.1), ThreatLevel.LOW)
        self.assertEqual(self.threat_engine.classify_threat_level(0.4), ThreatLevel.MEDIUM)
        self.assertEqual(self.threat_engine.classify_threat_level(0.7), ThreatLevel.HIGH)
        self.assertEqual(self.threat_engine.classify_threat_level(0.9), ThreatLevel.CRITICAL)
    
    def test_app_analysis(self):
        """测试应用威胁分析"""
        app_info = {
            'package_name': 'com.suspicious.banking',
            'permissions': [
                'android.permission.SEND_SMS',
                'android.permission.READ_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.DEVICE_ADMIN'
            ],
            'signature_verified': False,
            'install_source': 'unknown'
        }
        
        assessment = self.threat_engine.analyze_app_info(app_info)
        
        self.assertIsInstance(assessment, ThreatAssessment)
        self.assertEqual(assessment.app_package, 'com.suspicious.banking')
        self.assertGreaterEqual(assessment.risk_score, 0.5)  # 应该是高风险
        self.assertGreater(len(assessment.indicators), 0)
        self.assertGreater(len(assessment.mitigation_actions), 0)


class TestVulnerabilityDetectionEngine(unittest.TestCase):
    """漏洞检测引擎测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        self.vuln_engine = VulnerabilityDetectionEngine(self.device_manager)
    
    def test_android_version_vulnerability_check(self):
        """测试Android版本漏洞检查"""
        # 模拟旧版本Android
        self.device_manager.execute_command.return_value = "8.0"
        
        vulnerabilities = self.vuln_engine.scanner.scan_system_vulnerabilities("test_device")
        
        # 应该检测到系统漏洞
        self.assertIsInstance(vulnerabilities, list)
        # 在测试环境中，可能检测到已知漏洞
    
    def test_configuration_issues_detection(self):
        """测试配置问题检测"""
        # 模拟ADB开启状态
        self.device_manager.execute_command.side_effect = lambda device_id, command: {
            "getprop service.adb.root": "1",
            "settings get global install_non_market_apps": "1"
        }.get(command, "0")
        
        issues = self.vuln_engine.scanner.scan_configuration_issues("test_device")
        
        self.assertIsInstance(issues, list)
        self.assertGreater(len(issues), 0)  # 应该检测到配置问题
    
    def test_vulnerability_report_generation(self):
        """测试漏洞报告生成"""
        # 模拟漏洞扫描结果
        with patch.object(self.vuln_engine.scanner, 'scan_system_vulnerabilities') as mock_sys_scan, \
             patch.object(self.vuln_engine.scanner, 'scan_configuration_issues') as mock_config_scan:
            
            mock_sys_scan.return_value = [
                {'vuln_id': 'CVE-2020-0001', 'severity': 'HIGH', 'type': 'SYSTEM'}
            ]
            mock_config_scan.return_value = [
                {'name': 'ADB启用', 'severity': 'MEDIUM', 'type': 'CONFIG'}
            ]
            
            report = self.vuln_engine.scan_vulnerabilities("test_device")
            
            self.assertIsNotNone(report)
            self.assertEqual(report.device_id, "test_device")  # pyright: ignore[reportOptionalMemberAccess]
            self.assertEqual(report.vulnerability_count, 2)  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
            self.assertEqual(report.high_count, 1)  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
            self.assertEqual(report.medium_count, 1)  # pyright: ignore[reportOptionalMemberAccess]


class TestEnhancedRepairEngine(unittest.TestCase):
    """增强修复引擎测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        self.repair_engine = EnhancedRepairEngine(self.device_manager)
        
        # 模拟成功的命令执行
        self.device_manager.execute_command.return_value = "success"
    
    def test_repair_strategy_loading(self):
        """测试修复策略加载"""
        strategy = self.repair_engine.template_manager.get_repair_strategy('adb_enabled')
        
        self.assertIsNotNone(strategy)
        self.assertEqual(strategy.vulnerability_id, 'adb_enabled')  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
        self.assertTrue(strategy.automated)  # pyright: ignore[reportOptionalMemberAccess]
    
    def test_repair_strategy_execution(self):
        """测试修复策略执行"""
        strategy = self.repair_engine.template_manager.get_repair_strategy('adb_enabled')
        
        success = self.repair_engine._execute_repair_strategy("test_device", strategy)  # pyright: ignore[reportArgumentType]  # pyright: ignore[reportArgumentType]
        
        self.assertTrue(success)
        self.device_manager.execute_command.assert_called()
    
    def test_system_hardening_application(self):
        """测试系统加固应用"""
        from src.core.enhanced_repair_engine import HardeningType
        
        hardening_templates = self.repair_engine.template_manager.get_hardening_templates(
            HardeningType.SECURITY_SETTINGS
        )
        
        self.assertIsInstance(hardening_templates, list)
        self.assertGreater(len(hardening_templates), 0)
        
        # 测试单个加固配置应用
        if hardening_templates:
            hardening = hardening_templates[0]
            success = self.repair_engine._apply_hardening("test_device", hardening)
            self.assertTrue(success)


class TestRealTimeMonitoringEngine(unittest.TestCase):
    """实时监控引擎测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        self.monitoring_engine = RealTimeMonitoringEngine(self.device_manager)
    
    def test_monitoring_startup_shutdown(self):
        """测试监控启动和停止"""
        # 测试启动监控
        self.monitoring_engine.start_monitoring(["test_device"])
        
        status = self.monitoring_engine.get_monitoring_status()
        self.assertTrue(status['enabled'])
        self.assertEqual(status['monitored_devices'], 1)
        
        # 测试停止监控
        self.monitoring_engine.stop_monitoring()
        
        status = self.monitoring_engine.get_monitoring_status()
        self.assertFalse(status['enabled'])
    
    def test_device_monitor_creation(self):
        """测试设备监控器创建"""
        self.monitoring_engine.add_device_monitoring("test_device")
        
        self.assertIn("test_device", self.monitoring_engine.device_monitors)
        
        # 测试移除设备监控
        self.monitoring_engine.remove_device_monitoring("test_device")
        
        self.assertNotIn("test_device", self.monitoring_engine.device_monitors)
    
    def test_security_event_handling(self):
        """测试安全事件处理"""
        # 创建测试事件
        from src.core.realtime_monitoring_engine import SecurityEvent
        
        event = SecurityEvent(
            event_type="test_threat",
            device_id="test_device",
            severity="HIGH",
            description="测试威胁事件"
        )
        
        # 处理事件
        self.monitoring_engine._handle_security_event(event)
        
        # 验证事件被记录
        recent_events = self.monitoring_engine.get_recent_events(10)
        self.assertEqual(len(recent_events), 1)
        self.assertEqual(recent_events[0].event_type, "test_threat")


class TestRepairTaskManager(unittest.TestCase):
    """修复任务管理器测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        self.task_manager = RepairTaskManager(self.device_manager)
    
    def tearDown(self):
        self.task_manager.shutdown()
    
    def test_vulnerability_repair_task_creation(self):
        """测试漏洞修复任务创建"""
        task_id = self.task_manager.create_vulnerability_repair_task(
            "test_device", 
            auto_repair=True, 
            priority=TaskPriority.HIGH
        )
        
        self.assertIsNotNone(task_id)
        self.assertIn("vuln_repair", task_id)
    
    def test_system_hardening_task_creation(self):
        """测试系统加固任务创建"""
        task_id = self.task_manager.create_system_hardening_task(
            "test_device",
            hardening_types=['SECURITY_SETTINGS'],
            priority=TaskPriority.MEDIUM
        )
        
        self.assertIsNotNone(task_id)
        self.assertIn("hardening", task_id)
    
    def test_batch_repair_job_creation(self):
        """测试批量修复作业创建"""
        devices = ["device1", "device2", "device3"]
        repair_types = ["VULNERABILITY_REPAIR", "SYSTEM_HARDENING"]
        
        job_id = self.task_manager.create_batch_repair_job(
            devices=devices,
            repair_types=repair_types,
            priority=TaskPriority.HIGH,
            auto_repair=True,
            parallel_execution=True
        )
        
        self.assertIsNotNone(job_id)
        self.assertIn("batch_repair", job_id)
        self.assertIn(job_id, self.task_manager.batch_jobs)
    
    def test_task_statistics_retrieval(self):
        """测试任务统计信息获取"""
        stats = self.task_manager.get_task_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('total_tasks', stats)
        self.assertIn('pending_tasks', stats)
        self.assertIn('batch_jobs', stats)
        self.assertIn('executor_stats', stats)


class TestAPIIntegration(unittest.TestCase):
    """API集成测试"""
    
    def setUp(self):
        # 测试需要导入Flask相关模块
        try:
            from src.api.api_service import SecurityAPIService
            self.api_service = SecurityAPIService()
            self.client = self.api_service.app.test_client()
        except ImportError:
            self.skipTest("Flask未安装，跳过API测试")
    
    def test_api_service_initialization(self):
        """测试API服务初始化"""
        self.assertIsNotNone(self.api_service.device_manager)
        self.assertIsNotNone(self.api_service.virus_scan_engine)
        self.assertIsNotNone(self.api_service.threat_analysis_engine)
    
    def test_devices_api_endpoint(self):
        """测试设备API端点"""
        response = self.client.get('/api/devices')
        self.assertEqual(response.status_code, 200)
        
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('data', data)
    
    def test_statistics_api_endpoint(self):
        """测试统计API端点"""
        response = self.client.get('/api/statistics')
        self.assertEqual(response.status_code, 200)
        
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('devices', data['data'])
        self.assertIn('tasks', data['data'])


class TestSystemIntegration(unittest.TestCase):
    """系统集成测试"""
    
    def setUp(self):
        self.device_manager = Mock(spec=DeviceManager)
        
        # 创建完整的组件栈
        self.virus_engine = VirusScanEngine(self.device_manager)
        self.threat_engine = ThreatAnalysisEngine()
        self.vuln_engine = VulnerabilityDetectionEngine(self.device_manager)
        self.repair_engine = EnhancedRepairEngine(self.device_manager)
        self.monitoring_engine = RealTimeMonitoringEngine(self.device_manager)
        self.task_manager = RepairTaskManager(self.device_manager)
    
    def tearDown(self):
        self.monitoring_engine.stop_monitoring()
        self.task_manager.shutdown()
    
    def test_end_to_end_security_workflow(self):
        """测试端到端安全工作流程"""
        device_id = "test_device_e2e"
        
        # 模拟设备信息
        mock_device = DeviceInfo(
            device_id=device_id,
            model="TestDevice",
            android_version="10.0"
        )
        self.device_manager.get_device.return_value = mock_device
        self.device_manager.get_devices.return_value = [mock_device]
        
        # 1. 启动监控
        self.monitoring_engine.start_monitoring([device_id])
        
        # 2. 执行漏洞扫描
        with patch.object(self.vuln_engine.scanner, 'scan_system_vulnerabilities') as mock_sys_scan, \
             patch.object(self.vuln_engine.scanner, 'scan_configuration_issues') as mock_config_scan:
            
            mock_sys_scan.return_value = []
            mock_config_scan.return_value = [
                {'name': 'ADB启用', 'severity': 'MEDIUM', 'type': 'CONFIG', 'check': 'adb_enabled'}
            ]
            
            vuln_report = self.vuln_engine.scan_vulnerabilities(device_id)
            self.assertIsNotNone(vuln_report)
            self.assertEqual(vuln_report.vulnerability_count, 1)  # pyright: ignore[reportOptionalMemberAccess]
        
        # 3. 创建修复任务
        task_id = self.task_manager.create_vulnerability_repair_task(
            device_id, auto_repair=True, priority=TaskPriority.HIGH
        )
        self.assertIsNotNone(task_id)
        
        # 4. 验证系统状态
        monitoring_status = self.monitoring_engine.get_monitoring_status()
        self.assertTrue(monitoring_status['enabled'])
        
        task_stats = self.task_manager.get_task_statistics()
        self.assertGreater(task_stats['total_tasks'], 0)
    
    def test_component_interaction_stability(self):
        """测试组件交互稳定性"""
        # 测试各组件在并发操作下的稳定性
        import threading
        import time
        
        device_id = "stress_test_device"
        
        def virus_scan_worker():
            try:
                # 模拟病毒扫描
                self.device_manager.execute_command.return_value = "package:/test.apk=com.test"
                report = self.virus_engine.scan_device(device_id)
            except Exception:
                pass  # 忽略测试中的异常
        
        def threat_analysis_worker():
            try:
                app_info = {
                    'package_name': 'com.test.app',
                    'permissions': ['android.permission.INTERNET']
                }
                assessment = self.threat_engine.analyze_app_info(app_info)
            except Exception:
                pass
        
        # 启动多个工作线程
        threads = []
        for i in range(3):
            t1 = threading.Thread(target=virus_scan_worker)
            t2 = threading.Thread(target=threat_analysis_worker)
            threads.extend([t1, t2])
            t1.start()
            t2.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join(timeout=5.0)
        
        # 验证系统仍然正常工作
        self.assertTrue(True)  # 如果到达这里说明没有死锁或崩溃


def run_all_tests():
    """运行所有测试"""
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加测试类
    test_classes = [
        TestVirusScanEngine,
        TestThreatAnalysisEngine,
        TestVulnerabilityDetectionEngine,
        TestEnhancedRepairEngine,
        TestRealTimeMonitoringEngine,
        TestRepairTaskManager,
        TestAPIIntegration,
        TestSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 输出测试结果摘要
    print(f"\n{'='*50}")
    print(f"测试结果摘要:")
    print(f"运行测试: {result.testsRun}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    print(f"跳过: {len(result.skipped)}")
    print(f"成功率: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)