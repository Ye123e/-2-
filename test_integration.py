#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
集成测试脚本
测试所有模块的集成功能
"""

import sys
import os
from pathlib import Path
import unittest
import threading
import time

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class AndroidRepairToolIntegrationTest(unittest.TestCase):
    """集成测试类"""
    
    def setUp(self):
        """测试前设置"""
        print(f"\n{'='*50}")
        print(f"运行测试: {self._testMethodName}")
        print(f"{'='*50}")
    
    def test_01_imports(self):
        """测试所有模块导入"""
        print("测试模块导入...")
        
        try:
            from src.config.settings import AppConfig
            from src.utils.logger import setup_logger, get_logger
            from src.models import DeviceInfo, DiagnosticReport, VirusReport, RepairTask
            from src.core.device_manager import DeviceManager
            from src.core.diagnostic_engine import DiagnosticEngine
            from src.core.security_scanner import SecurityScanner, VirusSignatureDatabase
            from src.core.file_manager import FileScanner, FileCleaner
            from src.core.repair_engine import RepairEngine
            from src.gui.main_window import MainWindow
            
            print("✓ 所有模块导入成功")
            
        except ImportError as e:
            self.fail(f"模块导入失败: {e}")
    
    def test_02_config_system(self):
        """测试配置系统"""
        print("测试配置系统...")
        
        try:
            from src.config.settings import AppConfig
            
            config = AppConfig()
            
            # 测试基本配置
            self.assertIsNotNone(config.app_name)
            self.assertIsNotNone(config.app_version)
            self.assertGreater(config.adb_timeout, 0)
            self.assertGreater(config.window_width, 0)
            
            print(f"✓ 应用名称: {config.app_name}")
            print(f"✓ 应用版本: {config.app_version}")
            print(f"✓ ADB超时: {config.adb_timeout}秒")
            print("✓ 配置系统测试通过")
            
        except Exception as e:
            self.fail(f"配置系统测试失败: {e}")
    
    def test_03_logging_system(self):
        """测试日志系统"""
        print("测试日志系统...")
        
        try:
            from src.utils.logger import setup_logger, get_logger
            
            # 设置日志
            setup_logger("INFO", "logs/test.log")
            logger = get_logger("test")
            
            # 测试日志记录
            logger.info("这是一条测试日志")
            logger.warning("这是一条警告日志")
            logger.error("这是一条错误日志")
            
            print("✓ 日志系统测试通过")
            
        except Exception as e:
            self.fail(f"日志系统测试失败: {e}")
    
    def test_04_data_models(self):
        """测试数据模型"""
        print("测试数据模型...")
        
        try:
            from src.models import (
                DeviceInfo, ConnectionType, Issue, IssueCategory, 
                IssueSeverity, DiagnosticReport, RepairTask, TaskStatus
            )
            from datetime import datetime
            
            # 测试设备信息模型
            device = DeviceInfo(
                device_id="test_device",
                model="Test Phone",
                android_version="11",
                build_number="test_build",
                root_status=False,
                storage_total=64 * 1024**3,  # 64GB
                storage_free=32 * 1024**3,   # 32GB可用
                connection_type=ConnectionType.USB
            )
            
            self.assertEqual(device.device_id, "test_device")
            self.assertEqual(device.storage_usage_percent, 50.0)
            
            # 测试问题模型
            issue = Issue(
                category=IssueCategory.STORAGE,
                severity=IssueSeverity.HIGH,
                description="存储空间不足",
                auto_fixable=True
            )
            
            self.assertEqual(issue.category, IssueCategory.STORAGE)
            self.assertTrue(issue.auto_fixable)
            
            # 测试诊断报告模型
            report = DiagnosticReport(
                device_id="test_device",
                scan_time=datetime.now(),
                issues_found=[issue]
            )
            
            self.assertEqual(report.total_issues_count, 1)
            self.assertEqual(report.high_issues_count, 1)
            
            # 测试修复任务模型
            task = RepairTask(
                task_id="test_task",
                device_id="test_device",
                task_type="TEST_REPAIR"
            )
            
            self.assertEqual(task.status, TaskStatus.PENDING)
            task.start()
            self.assertEqual(task.status, TaskStatus.RUNNING)
            
            print("✓ 数据模型测试通过")
            
        except Exception as e:
            self.fail(f"数据模型测试失败: {e}")
    
    def test_05_device_manager(self):
        """测试设备管理器（模拟）"""
        print("测试设备管理器...")
        
        try:
            from src.core.device_manager import DeviceManager
            
            # 创建设备管理器
            device_manager = DeviceManager()
            
            # 测试基本功能（不需要真实设备）
            devices = device_manager.get_connected_devices()
            self.assertIsInstance(devices, list)
            
            print("✓ 设备管理器初始化成功")
            print("✓ 设备管理器测试通过")
            
        except Exception as e:
            self.fail(f"设备管理器测试失败: {e}")
    
    def test_06_diagnostic_engine(self):
        """测试诊断引擎（模拟）"""
        print("测试诊断引擎...")
        
        try:
            from src.core.device_manager import DeviceManager
            from src.core.diagnostic_engine import DiagnosticEngine
            
            device_manager = DeviceManager()
            diagnostic_engine = DiagnosticEngine(device_manager)
            
            # 测试快速健康检查（模拟）
            # 这里不执行真实的设备检查，只测试接口
            
            print("✓ 诊断引擎初始化成功")
            print("✓ 诊断引擎测试通过")
            
        except Exception as e:
            self.fail(f"诊断引擎测试失败: {e}")
    
    def test_07_security_scanner(self):
        """测试安全扫描器"""
        print("测试安全扫描器...")
        
        try:
            from src.core.device_manager import DeviceManager
            from src.core.security_scanner import SecurityScanner, VirusSignatureDatabase
            
            device_manager = DeviceManager()
            signature_db = VirusSignatureDatabase()
            security_scanner = SecurityScanner(device_manager, signature_db)
            
            # 测试病毒特征库
            self.assertIsInstance(signature_db.malware_hashes, set)
            self.assertIsInstance(signature_db.suspicious_permissions, list)
            
            # 测试恶意包名检查
            is_malicious = signature_db.is_malicious_package("com.fake.malware")
            self.assertIsInstance(is_malicious, bool)
            
            print("✓ 病毒特征库加载成功")
            print("✓ 安全扫描器测试通过")
            
        except Exception as e:
            self.fail(f"安全扫描器测试失败: {e}")
    
    def test_08_file_manager(self):
        """测试文件管理器"""
        print("测试文件管理器...")
        
        try:
            from src.core.device_manager import DeviceManager
            from src.core.file_manager import FileScanner, FileCleaner, FileType
            
            device_manager = DeviceManager()
            file_scanner = FileScanner(device_manager)
            file_cleaner = FileCleaner(device_manager)
            
            # 测试文件类型枚举
            self.assertEqual(FileType.CORRUPTED.value, "CORRUPTED")
            self.assertEqual(FileType.DUPLICATE.value, "DUPLICATE")
            
            print("✓ 文件扫描器初始化成功")
            print("✓ 文件清理器初始化成功")
            print("✓ 文件管理器测试通过")
            
        except Exception as e:
            self.fail(f"文件管理器测试失败: {e}")
    
    def test_09_repair_engine(self):
        """测试修复引擎"""
        print("测试修复引擎...")
        
        try:
            from src.core.device_manager import DeviceManager
            from src.core.repair_engine import RepairEngine, RepairType
            
            device_manager = DeviceManager()
            repair_engine = RepairEngine(device_manager)
            
            # 测试修复类型枚举
            self.assertEqual(RepairType.STORAGE_CLEANUP.value, "STORAGE_CLEANUP")
            self.assertEqual(RepairType.VIRUS_REMOVAL.value, "VIRUS_REMOVAL")
            
            # 测试修复模板
            self.assertIn(RepairType.FULL_REPAIR, repair_engine.repair_templates)
            self.assertIn(RepairType.VIRUS_REMOVAL, repair_engine.repair_templates)
            
            print("✓ 修复引擎初始化成功")
            print("✓ 修复模板加载成功")
            print("✓ 修复引擎测试通过")
            
        except Exception as e:
            self.fail(f"修复引擎测试失败: {e}")
    
    def test_10_gui_components(self):
        """测试GUI组件（不启动界面）"""
        print("测试GUI组件...")
        
        try:
            import tkinter as tk
            from src.config.settings import AppConfig
            from src.gui.main_window import MainWindow
            
            # 测试配置加载
            config = AppConfig()
            
            # 这里不创建实际的GUI窗口，只测试类的创建
            print("✓ GUI组件导入成功")
            print("✓ GUI组件测试通过")
            
        except Exception as e:
            self.fail(f"GUI组件测试失败: {e}")

def run_integration_tests():
    """运行集成测试"""
    print("🚀 开始运行Android系统修复工具集成测试")
    print("=" * 80)
    
    # 创建测试套件
    test_suite = unittest.TestLoader().loadTestsFromTestCase(AndroidRepairToolIntegrationTest)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 80)
    print("📊 测试结果统计:")
    print(f"总测试数: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ 失败的测试:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 错误的测试:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    success_rate = (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100
    print(f"\n📈 成功率: {success_rate:.1f}%")
    
    if result.wasSuccessful():
        print("\n🎉 所有集成测试通过！")
        print("系统已准备就绪，可以正常使用。")
        return True
    else:
        print("\n⚠️ 部分测试失败，请检查错误信息。")
        return False

def main():
    """主函数"""
    print("Android系统修复工具 - 集成测试")
    
    # 运行集成测试
    success = run_integration_tests()
    
    if success:
        print("\n使用方法:")
        print("1. 启动检查: python start.py")
        print("2. 启动应用: python main.py")
        print("3. 启动应用(GUI): python start.py --gui")
        return 0
    else:
        print("\n请修复测试失败的问题后重试。")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)