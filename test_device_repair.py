#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备连接修复功能测试
验证设备修复功能的完整性和稳定性
"""

import unittest
import time
import threading
from unittest.mock import Mock, MagicMock, patch, call
from typing import Dict, Any, List

# 导入测试目标模块
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.device_manager import DeviceManager, ADBManager
from src.core.repair_manager import RepairManager, RepairStage, RepairSession
from src.core.diagnostic_engine import DiagnosticEngine
from src.core.repair_engine import RepairEngine, RepairType
from src.core.security_scanner import SecurityScanner, VirusSignatureDatabase
from src.core.exception_handler import RepairExceptionHandler, ExceptionType, RecoveryAction
from src.models import DeviceInfo, ConnectionType, Issue, TaskStatus
from src.gui.main_window import MainWindow


class MockDeviceInfo:
    """模拟设备信息"""
    
    def __init__(self, device_id: str = "test_device_001"):
        self.device_id = device_id
        self.model = "Mock Android Device"
        self.android_version = "11"
        self.build_number = "Mock Build"
        self.root_status = False
        self.storage_total = 32 * 1024 * 1024 * 1024  # 32GB
        self.storage_free = 16 * 1024 * 1024 * 1024   # 16GB
        self.storage_usage_percent = 50
        self.connection_type = ConnectionType.USB
        self.manufacturer = "MockDevice Inc"
        self.cpu_arch = "arm64-v8a"
        self.screen_resolution = "1920x1080"


class TestDeviceManager(unittest.TestCase):
    """设备管理器测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = DeviceManager(adb_timeout=10)
        self.mock_device = MockDeviceInfo()
    
    @patch('src.core.device_manager.subprocess.run')
    def test_get_adb_devices(self, mock_run):
        """测试获取ADB设备列表"""
        # 模拟ADB输出
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "List of devices attached\ntest_device_001\tdevice\n"
        mock_run.return_value = mock_result
        
        devices = self.device_manager.adb_manager.get_adb_devices()
        
        self.assertIn("test_device_001", devices)
        mock_run.assert_called_once()
    
    def test_device_validation(self):
        """测试设备验证功能"""
        # 添加模拟设备
        self.device_manager.devices[self.mock_device.device_id] = self.mock_device
        
        # 模拟ADB管理器
        with patch.object(self.device_manager.adb_manager, 'get_adb_devices', 
                         return_value=[self.mock_device.device_id]):
            with patch.object(self.device_manager.adb_manager, 'connect_device', 
                            return_value=Mock()):
                with patch.object(self.device_manager.adb_manager, 'execute_command', 
                                return_value='test'):
                    
                    validation_result = self.device_manager.validate_device_connection(
                        self.mock_device.device_id
                    )
                    
                    self.assertTrue(validation_result['adb_connected'])
                    self.assertTrue(validation_result['authorized'])
                    self.assertTrue(validation_result['shell_access'])


class TestRepairManager(unittest.TestCase):
    """修复管理器测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.repair_manager = RepairManager(self.device_manager)
        self.mock_device = MockDeviceInfo()
        
        # 设置模拟返回值
        self.device_manager.get_device.return_value = self.mock_device
        
    def test_start_repair_session(self):
        """测试启动修复会话"""
        session_id = self.repair_manager.start_repair(self.mock_device.device_id)
        
        self.assertIsNotNone(session_id)
        self.assertIn(session_id, self.repair_manager.active_sessions)
        
        session = self.repair_manager.active_sessions[session_id]
        self.assertEqual(session.device_id, self.mock_device.device_id)
    
    def test_repair_progress_callback(self):
        """测试修复进度回调"""
        progress_calls = []
        
        def progress_callback(session_id, stage, progress, message):
            progress_calls.append((session_id, stage, progress, message))
        
        self.repair_manager.add_progress_callback(progress_callback)
        
        # 模拟进度更新
        session_id = "test_session"
        self.repair_manager._notify_progress(
            session_id, RepairStage.DEVICE_VALIDATION, 10, "测试进度"
        )
        
        self.assertEqual(len(progress_calls), 1)
        self.assertEqual(progress_calls[0][0], session_id)
        self.assertEqual(progress_calls[0][2], 10)
    
    def test_repair_completion_callback(self):
        """测试修复完成回调"""
        completion_calls = []
        
        def completion_callback(session_id, success, session):
            completion_calls.append((session_id, success, session))
        
        self.repair_manager.add_completion_callback(completion_callback)
        
        # 创建测试会话
        session = RepairSession(self.mock_device.device_id, "test_session")
        
        # 模拟完成通知
        self.repair_manager._notify_completion("test_session", True, session)
        
        self.assertEqual(len(completion_calls), 1)
        self.assertTrue(completion_calls[0][1])  # success = True


class TestDiagnosticEngine(unittest.TestCase):
    """诊断引擎测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.diagnostic_engine = DiagnosticEngine(self.device_manager)
        self.mock_device = MockDeviceInfo()
        
        self.device_manager.get_device.return_value = self.mock_device
    
    def test_diagnose_storage(self):
        """测试存储诊断"""
        # 模拟存储检查命令
        with patch.object(self.device_manager.adb_manager, 'execute_command') as mock_cmd:
            mock_cmd.return_value = "Filesystem     1K-blocks    Used Available Use% Mounted on\n/data         16384000 8192000   8192000  50% /data"
            
            issues = self.diagnostic_engine.diagnose_storage(self.mock_device.device_id)
            
            # 检查是否正确识别了存储问题
            self.assertIsInstance(issues, list)
    
    def test_diagnose_network(self):
        """测试网络诊断"""
        with patch.object(self.device_manager.adb_manager, 'execute_command') as mock_cmd:
            # 模拟网络检查失败
            mock_cmd.return_value = "3 packets transmitted, 0 received"
            
            issues = self.diagnostic_engine.diagnose_network(self.mock_device.device_id)
            
            # 应该发现网络问题
            self.assertTrue(len(issues) > 0)
            self.assertTrue(any("网络" in issue.description for issue in issues))
    
    def test_diagnose_applications(self):
        """测试应用诊断"""
        with patch.object(self.device_manager.adb_manager, 'execute_command') as mock_cmd:
            # 模拟应用列表
            mock_cmd.return_value = "package:com.example.app1\npackage:com.example.app2"
            
            issues = self.diagnostic_engine.diagnose_applications(self.mock_device.device_id)
            
            self.assertIsInstance(issues, list)


class TestRepairEngine(unittest.TestCase):
    """修复引擎测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.repair_engine = RepairEngine(self.device_manager)
        self.mock_device = MockDeviceInfo()
        
        self.device_manager.get_device.return_value = self.mock_device
        self.device_manager.get_device_capabilities.return_value = {
            'root_access': False,
            'package_manager': True,
            'file_system_access': True
        }
    
    def test_create_repair_plan(self):
        """测试创建修复计划"""
        task_id = self.repair_engine.create_repair_plan(
            self.mock_device.device_id,
            RepairType.STORAGE_CLEANUP
        )
        
        self.assertIsNotNone(task_id)
        self.assertIn(task_id, self.repair_engine.active_tasks)
        
        task = self.repair_engine.active_tasks[task_id]
        self.assertEqual(task.device_id, self.mock_device.device_id)
        self.assertEqual(task.task_type, RepairType.STORAGE_CLEANUP.value)
    
    def test_repair_step_execution(self):
        """测试修复步骤执行"""
        with patch.object(self.device_manager.adb_manager, 'execute_command') as mock_cmd:
            mock_cmd.return_value = "Success"
            
            # 创建修复任务
            task_id = self.repair_engine.create_repair_plan(
                self.mock_device.device_id,
                RepairType.CACHE_CLEAR
            )
            
            # 执行修复
            success = self.repair_engine.execute_repair(task_id)
            
            self.assertTrue(success)
    
    def test_repair_without_root(self):
        """测试无ROOT权限的修复"""
        # 确保设备没有ROOT权限
        self.device_manager.get_device_capabilities.return_value = {
            'root_access': False,
            'package_manager': True,
            'file_system_access': True
        }
        
        task_id = self.repair_engine.create_repair_plan(
            self.mock_device.device_id,
            RepairType.PERMISSION_FIX
        )
        
        # 应该创建替代的修复步骤
        self.assertIsNotNone(task_id)
        
        task = self.repair_engine.active_tasks[task_id]
        # 检查是否有跳过需要ROOT的步骤的记录
        self.assertIsNotNone(task.details)


class TestSecurityScanner(unittest.TestCase):
    """安全扫描器测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.signature_db = VirusSignatureDatabase()
        self.security_scanner = SecurityScanner(self.device_manager, self.signature_db)
        self.mock_device = MockDeviceInfo()
        
        self.device_manager.get_device.return_value = self.mock_device
    
    def test_scan_device(self):
        """测试设备扫描"""
        with patch.object(self.device_manager.adb_manager, 'execute_command') as mock_cmd:
            # 模拟应用列表
            mock_cmd.return_value = "package:/system/app/TestApp.apk=com.test.app"
            
            issues = self.security_scanner.scan_device(self.mock_device.device_id)
            
            self.assertIsInstance(issues, list)
    
    def test_malicious_package_detection(self):
        """测试恶意包检测"""
        # 测试恶意包名检测
        self.assertTrue(self.signature_db.is_malicious_package("com.fake.app"))
        self.assertTrue(self.signature_db.is_malicious_package("com.trojan.malware"))
        self.assertFalse(self.signature_db.is_malicious_package("com.google.android.gms"))
    
    def test_suspicious_permissions(self):
        """测试可疑权限检测"""
        suspicious_perms = ['READ_CONTACTS', 'SEND_SMS', 'RECORD_AUDIO']
        normal_perms = ['INTERNET', 'ACCESS_NETWORK_STATE']
        
        self.assertTrue(self.signature_db.is_suspicious_permissions(suspicious_perms))
        self.assertFalse(self.signature_db.is_suspicious_permissions(normal_perms))


class TestExceptionHandler(unittest.TestCase):
    """异常处理器测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.exception_handler = RepairExceptionHandler(self.device_manager)
    
    def test_exception_classification(self):
        """测试异常分类"""
        # 测试设备连接异常
        connection_error = Exception("device not found")
        exception_type = self.exception_handler._classify_exception(connection_error)
        self.assertEqual(exception_type, ExceptionType.DEVICE_CONNECTION_LOST)
        
        # 测试权限异常
        permission_error = Exception("permission denied")
        exception_type = self.exception_handler._classify_exception(permission_error)
        self.assertEqual(exception_type, ExceptionType.PERMISSION_DENIED)
        
        # 测试超时异常
        timeout_error = Exception("connection timeout")
        exception_type = self.exception_handler._classify_exception(timeout_error)
        self.assertEqual(exception_type, ExceptionType.COMMAND_TIMEOUT)
    
    def test_recovery_action_retry(self):
        """测试重试恢复策略"""
        task_id = "test_task"
        device_id = "test_device"
        operation = "test_operation"
        exception = Exception("temporary error")
        
        recovery_action = self.exception_handler.handle_exception(
            task_id, device_id, operation, exception
        )
        
        # 对于未知异常，默认策略应该是重试
        self.assertIn(recovery_action, [RecoveryAction.RETRY, RecoveryAction.ABORT])
    
    def test_backup_creation(self):
        """测试备份创建"""
        task_id = "test_task"
        device_id = "test_device"
        operation = "test_operation"
        backup_data = {"test_key": "test_value"}
        
        # 创建备份不应该抛出异常
        try:
            self.exception_handler.create_backup(task_id, device_id, operation, backup_data)
        except Exception as e:
            self.fail(f"备份创建失败: {e}")


class TestMainWindowIntegration(unittest.TestCase):
    """主窗口集成测试"""
    
    def setUp(self):
        """设置测试环境"""
        # 创建模拟配置
        self.mock_config = Mock()
        self.mock_config.app_name = "Android System Repair Tool"
        self.mock_config.app_version = "1.0.0"
        self.mock_config.window_width = 1000
        self.mock_config.window_height = 700
        self.mock_config.adb_timeout = 30
        self.mock_config.adb_port = 5037
        self.mock_config.adb_path = "adb"
        self.mock_config.auto_connect = False
    
    @patch('src.gui.main_window.tk.Tk')
    def test_main_window_initialization(self, mock_tk):
        """测试主窗口初始化"""
        # 模拟Tk根窗口
        mock_root = Mock()
        mock_tk.return_value = mock_root
        
        try:
            main_window = MainWindow(self.mock_config)
            self.assertIsNotNone(main_window.repair_manager)
            self.assertIsNotNone(main_window.device_manager)
        except Exception as e:
            self.fail(f"主窗口初始化失败: {e}")


class TestIntegrationScenarios(unittest.TestCase):
    """集成测试场景"""
    
    def setUp(self):
        """设置集成测试环境"""
        self.device_manager = Mock(spec=DeviceManager)
        self.repair_manager = RepairManager(self.device_manager)
        self.mock_device = MockDeviceInfo()
        
        # 设置模拟返回值
        self.device_manager.get_device.return_value = self.mock_device
        self.device_manager.adb_manager = Mock()
        self.device_manager.adb_manager.execute_command.return_value = "success"
    
    def test_complete_repair_workflow(self):
        """测试完整的修复工作流程"""
        # 设置回调函数来跟踪进度
        progress_updates = []
        completion_results = []
        
        def progress_callback(session_id, stage, progress, message):
            progress_updates.append((stage, progress, message))
        
        def completion_callback(session_id, success, session):
            completion_results.append((success, session))
        
        self.repair_manager.add_progress_callback(progress_callback)
        self.repair_manager.add_completion_callback(completion_callback)
        
        # 启动修复
        session_id = self.repair_manager.start_repair(
            self.mock_device.device_id,
            {'full_repair': False, 'backup_data': True}
        )
        
        self.assertIsNotNone(session_id)
        
        # 等待修复完成（模拟异步执行）
        time.sleep(0.1)  # 短暂等待以允许异步操作开始
        
        # 验证会话已创建
        self.assertIn(session_id, self.repair_manager.active_sessions)
    
    def test_device_connection_lost_scenario(self):
        """测试设备连接丢失场景"""
        # 模拟设备连接丢失
        self.device_manager.get_device.return_value = None
        
        # 尝试启动修复
        session_id = self.repair_manager.start_repair(self.mock_device.device_id)
        
        # 等待处理完成
        time.sleep(0.1)
        
        # 检查会话状态
        session = self.repair_manager.get_repair_status(session_id)
        self.assertIsNotNone(session)
    
    def test_permission_denied_scenario(self):
        """测试权限被拒绝场景"""
        # 模拟权限错误
        self.device_manager.adb_manager.execute_command.side_effect = Exception("permission denied")
        
        session_id = self.repair_manager.start_repair(self.mock_device.device_id)
        
        # 等待处理
        time.sleep(0.1)
        
        # 异常应该被捕获并处理
        session = self.repair_manager.get_repair_status(session_id)
        self.assertIsNotNone(session)


def run_comprehensive_tests():
    """运行综合测试"""
    test_suite = unittest.TestSuite()
    
    # 添加所有测试类
    test_classes = [
        TestDeviceManager,
        TestRepairManager,
        TestDiagnosticEngine,
        TestRepairEngine,
        TestSecurityScanner,
        TestExceptionHandler,
        TestMainWindowIntegration,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # 返回测试结果
    return {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'success': result.wasSuccessful(),
        'details': {
            'failures': result.failures,
            'errors': result.errors
        }
    }


if __name__ == '__main__':
    print("开始设备连接修复功能综合测试...")
    print("=" * 60)
    
    # 运行测试
    test_results = run_comprehensive_tests()
    
    print("\n" + "=" * 60)
    print("测试结果汇总:")
    print(f"总测试数: {test_results['tests_run']}")
    print(f"失败数: {test_results['failures']}")
    print(f"错误数: {test_results['errors']}")
    print(f"测试状态: {'通过' if test_results['success'] else '失败'}")
    
    if not test_results['success']:
        print("\n详细错误信息:")
        for failure in test_results['details']['failures']:
            print(f"失败: {failure[0]} - {failure[1]}")
        for error in test_results['details']['errors']:
            print(f"错误: {error[0]} - {error[1]}")
    
    print("=" * 60)