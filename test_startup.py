#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动测试脚本
验证闪退修复系统的完整功能
"""

import sys
import os
import tempfile
import time
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_dependency_check():
    """测试依赖检查功能"""
    print("=" * 50)
    print("测试依赖检查功能")
    print("=" * 50)
    
    try:
        from src.utils.dependency_checker import quick_check, detailed_check
        
        print("1. 执行快速检查...")
        quick_result = quick_check()
        print(f"   快速检查结果: {'✅ 通过' if quick_result else '⚠️ 有问题'}")
        
        print("2. 执行详细检查...")
        detailed_results = detailed_check()
        print(f"   详细检查项目数: {len(detailed_results)}")
        
        if 'summary' in detailed_results:
            summary = detailed_results['summary']
            print(f"   检查总结: {summary.message}")
        
        print("✅ 依赖检查功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 依赖检查功能异常: {e}")
        return False

def test_config_validation():
    """测试配置验证功能"""
    print("\n" + "=" * 50)
    print("测试配置验证功能")
    print("=" * 50)
    
    try:
        from src.utils.config_validator import validate_config_file, ConfigValidator
        import configparser
        
        # 创建测试配置文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write("""
[app]
name = Android系统修复工具
version = 1.0.0

[logging]
level = INFO
file = logs/app.log

[adb]
timeout = 30
port = 5037
            """)
            test_config_file = f.name
        
        try:
            print("1. 验证有效配置...")
            is_valid, results = validate_config_file(test_config_file)
            print(f"   配置验证结果: {'✅ 有效' if is_valid else '⚠️ 有问题'}")
            print(f"   验证项目数: {len(results)}")
            
            print("2. 测试配置修复...")
            validator = ConfigValidator()
            default_config = validator.create_default_config()
            print(f"   默认配置节数: {len(default_config.sections())}")
            
            print("✅ 配置验证功能正常")
            return True
            
        finally:
            os.unlink(test_config_file)
            
    except Exception as e:
        print(f"❌ 配置验证功能异常: {e}")
        return False

def test_exception_recovery():
    """测试异常恢复功能"""
    print("\n" + "=" * 50)
    print("测试异常恢复功能")
    print("=" * 50)
    
    try:
        from src.utils.exception_recovery import (
            get_global_recovery_manager, exception_handler, RecoveryAction
        )
        
        print("1. 获取全局恢复管理器...")
        manager = get_global_recovery_manager()
        print(f"   恢复策略数: {len(manager.recovery_strategies)}")
        
        print("2. 测试装饰器功能...")
        
        @exception_handler(recovery_action=RecoveryAction.RETRY, max_retries=2)
        def test_function():
            # 模拟一个函数
            return "成功执行"
        
        result = test_function()
        print(f"   装饰器测试结果: {result}")
        
        print("3. 测试异常统计...")
        stats = manager.get_exception_statistics()
        print(f"   异常统计: {stats['total_exceptions']} 个异常")
        
        print("✅ 异常恢复功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 异常恢复功能异常: {e}")
        return False

def test_error_dialog():
    """测试错误对话框功能"""
    print("\n" + "=" * 50)
    print("测试错误对话框功能")
    print("=" * 50)
    
    try:
        from src.utils.error_dialog import ErrorDialogManager, create_error_solution
        
        print("1. 创建错误对话框管理器...")
        dialog_manager = ErrorDialogManager()
        print("   对话框管理器创建成功")
        
        print("2. 测试异常翻译...")
        test_exception = FileNotFoundError("测试文件未找到")
        error_info = dialog_manager.translator.translate_exception(test_exception)
        print(f"   错误翻译: {error_info.title}")
        print(f"   解决方案数: {len(error_info.solutions)}")
        
        print("3. 测试解决方案创建...")
        solution = create_error_solution(
            title="测试解决方案",
            description="这是一个测试",
            steps=["步骤1", "步骤2"]
        )
        print(f"   解决方案: {solution.title}")
        
        print("✅ 错误对话框功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 错误对话框功能异常: {e}")
        return False

def test_health_monitor():
    """测试健康监控功能"""
    print("\n" + "=" * 50)
    print("测试健康监控功能")
    print("=" * 50)
    
    try:
        from src.utils.health_monitor import (
            get_health_monitor, SystemHealthMonitor, HealthStatus
        )
        
        print("1. 获取健康监控器...")
        monitor = get_health_monitor()
        print(f"   监控指标数: {len(monitor.metrics)}")
        
        print("2. 收集性能指标...")
        monitor._collect_metrics()
        print("   指标收集完成")
        
        print("3. 获取健康状态...")
        health_status = monitor.get_overall_health()
        print(f"   健康状态: {health_status.value}")
        
        print("4. 生成健康报告...")
        report = monitor.get_health_report()
        print(f"   报告项目数: {len(report)}")
        print(f"   运行时间: {report['uptime_formatted']}")
        
        print("✅ 健康监控功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 健康监控功能异常: {e}")
        return False

def test_enhanced_logging():
    """测试增强日志功能"""
    print("\n" + "=" * 50)
    print("测试增强日志功能")
    print("=" * 50)
    
    try:
        from src.utils.logger import setup_logger, LogConfig, get_log_stats
        
        print("1. 设置增强日志...")
        config = LogConfig(
            level="INFO",
            log_file="logs/test.log",
            enable_monitoring=True
        )
        logger = setup_logger(config=config)
        print("   日志设置完成")
        
        print("2. 测试日志记录...")
        logger.info("测试信息日志")
        logger.warning("测试警告日志")
        logger.error("测试错误日志")
        print("   日志记录完成")
        
        print("3. 获取日志统计...")
        time.sleep(0.1)  # 等待统计更新
        stats = get_log_stats()
        if stats:
            print(f"   总日志数: {stats['total_logs']}")
            print(f"   错误数: {stats['error_count']}")
        else:
            print("   日志统计暂未可用")
        
        print("✅ 增强日志功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 增强日志功能异常: {e}")
        return False

def test_integration():
    """测试组件集成"""
    print("\n" + "=" * 50)
    print("测试组件集成")
    print("=" * 50)
    
    try:
        # 模拟主程序的启动流程
        print("1. 模拟启动检查...")
        from src.utils.dependency_checker import quick_check
        from src.utils.config_validator import validate_config_file
        
        # 依赖检查
        dep_ok = quick_check()
        print(f"   依赖检查: {'✅' if dep_ok else '⚠️'}")
        
        # 配置验证
        config_file = "config.ini"
        if os.path.exists(config_file):
            config_ok, _ = validate_config_file(config_file)
            print(f"   配置验证: {'✅' if config_ok else '⚠️'}")
        else:
            print("   配置文件: ⚠️ 不存在")
        
        print("2. 初始化核心组件...")
        
        # 异常恢复管理器
        from src.utils.exception_recovery import get_global_recovery_manager
        recovery_manager = get_global_recovery_manager()
        print("   异常恢复管理器: ✅")
        
        # 健康监控
        from src.utils.health_monitor import get_health_monitor
        health_monitor = get_health_monitor()
        print("   健康监控器: ✅")
        
        # 日志系统
        from src.utils.logger import setup_logger
        logger = setup_logger()
        print("   日志系统: ✅")
        
        print("3. 测试组件协作...")
        
        # 模拟一个异常情况
        try:
            raise ValueError("模拟测试异常")
        except Exception as e:
            # 异常恢复系统记录
            context = recovery_manager._create_exception_context(
                e, type(e), e.__traceback__
            )
            print(f"   异常记录: ✅ ({context.exception_type.__name__})")
            
            # 错误对话框翻译
            from src.utils.error_dialog import ErrorDialogManager
            dialog_manager = ErrorDialogManager()
            error_info = dialog_manager.translator.translate_exception(e)
            print(f"   错误翻译: ✅ ({error_info.error_code})")
        
        # 健康状态检查
        health_status = health_monitor.get_overall_health()
        print(f"   健康状态: ✅ ({health_status.value})")
        
        print("✅ 组件集成测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 组件集成测试异常: {e}")
        return False

def main():
    """主测试函数"""
    print("Android系统修复工具 - 闪退修复系统测试")
    print("=" * 60)
    
    test_results = []
    
    # 运行所有测试
    tests = [
        ("依赖检查", test_dependency_check),
        ("配置验证", test_config_validation),
        ("异常恢复", test_exception_recovery),
        ("错误对话框", test_error_dialog),
        ("健康监控", test_health_monitor),
        ("增强日志", test_enhanced_logging),
        ("组件集成", test_integration)
    ]
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            test_results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name}测试发生异常: {e}")
            test_results.append((test_name, False))
    
    # 显示测试总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for test_name, result in test_results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"{test_name:12} : {status}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print("-" * 30)
    print(f"总计: {len(test_results)} 项测试")
    print(f"通过: {passed} 项")
    print(f"失败: {failed} 项")
    
    if failed == 0:
        print("\n🎉 所有测试通过！闪退修复系统工作正常。")
        return 0
    else:
        print(f"\n⚠️ 有 {failed} 项测试失败，请检查相关功能。")
        return 1

if __name__ == "__main__":
    sys.exit(main())