#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基本功能测试脚本
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """测试模块导入"""
    print("测试模块导入...")
    
    try:
        from src.config.settings import AppConfig
        print("✓ 配置模块导入成功")
        
        from src.core.device_manager import DeviceManager
        print("✓ 设备管理器导入成功")
        
        from src.core.diagnostic_engine import DiagnosticEngine
        print("✓ 诊断引擎导入成功")
        
        from src.core.security_scanner import SecurityScanner, VirusSignatureDatabase
        print("✓ 安全扫描器导入成功")
        
        from src.core.file_cleanup import FileCleanupEngine
        print("✓ 文件清理引擎导入成功")
        
        from src.core.resource_scanner import ResourceScanner
        print("✓ 资源扫描器导入成功")
        
        from src.core.repair_engine import RepairEngine
        print("✓ 修复引擎导入成功")
        
        from src.gui.main_window import MainWindow
        print("✓ GUI界面导入成功")
        
        return True
        
    except ImportError as e:
        print(f"✗ 模块导入失败: {e}")
        return False

def test_config():
    """测试配置系统"""
    print("\n测试配置系统...")
    
    try:
        from src.config.settings import AppConfig
        
        config = AppConfig()
        
        # 测试基本配置
        assert config.app_name == "Android系统修复工具"
        assert config.app_version == "1.0.0"
        assert config.adb_timeout == 30
        
        print("✓ 配置系统测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 配置系统测试失败: {e}")
        return False

def test_device_manager():
    """测试设备管理器"""
    print("\n测试设备管理器...")
    
    try:
        from src.core.device_manager import DeviceManager
        
        device_manager = DeviceManager()
        
        # 测试基本功能
        devices = device_manager.get_adb_devices()
        print(f"✓ 设备管理器初始化成功，检测到 {len(devices)} 个设备")
        
        return True
        
    except Exception as e:
        print(f"✗ 设备管理器测试失败: {e}")
        return False

def test_engines():
    """测试各个引擎"""
    print("\n测试各个引擎...")
    
    try:
        from src.core.device_manager import DeviceManager
        from src.core.diagnostic_engine import DiagnosticEngine
        from src.core.security_scanner import SecurityScanner, VirusSignatureDatabase
        from src.core.repair_engine import RepairEngine
        
        device_manager = DeviceManager()
        
        # 测试诊断引擎
        diagnostic_engine = DiagnosticEngine(device_manager)
        print("✓ 诊断引擎初始化成功")
        
        # 测试安全扫描器
        signature_db = VirusSignatureDatabase()
        security_scanner = SecurityScanner(device_manager, signature_db)
        print("✓ 安全扫描器初始化成功")
        
        # 测试修复引擎
        repair_engine = RepairEngine(device_manager)
        print("✓ 修复引擎初始化成功")
        
        return True
        
    except Exception as e:
        print(f"✗ 引擎测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("Android系统修复工具 - 基本功能测试")
    print("=" * 50)
    
    # 创建必要目录
    directories = [
        'logs', 'data', 'data/virus_signatures', 
        'data/system_resources', 'data/quarantine', 'backups'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # 运行测试
    tests = [
        test_imports,
        test_config,
        test_device_manager,
        test_engines
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        if test_func():
            passed += 1
    
    print(f"\n测试结果: {passed}/{total} 项测试通过")
    
    if passed == total:
        print("✓ 所有基本功能测试通过！")
        print("\n可以运行 'python start.py' 启动完整应用")
        return True
    else:
        print("✗ 部分测试失败，请检查相关模块")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)