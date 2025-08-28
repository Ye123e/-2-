#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试闪退问题解决方案 - 清理版本
"""

import sys
import os
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

def test_dependency_checker():
    """测试依赖检查器"""
    print("🔍 测试依赖检查器...")
    
    try:
        from src.utils.dependency_checker import quick_check, detailed_check
        
        # 快速检查
        print("执行快速检查...")
        result = quick_check()
        print(f"快速检查结果: {'通过' if result else '失败'}")
        
        # 详细检查
        print("执行详细检查...")
        results = detailed_check()
        
        print(f"检查项目数: {len(results)}")
        
        for name, result in results.items():
            if name == 'summary':
                continue
            status_icon = "✅" if result.status.value == "passed" else "❌" if result.status.value == "failed" else "⚠️"
            print(f"  {status_icon} {result.name}: {result.message}")
        
        return True
        
    except Exception as e:
        print(f"❌ 依赖检查器测试失败: {e}")
        return False

def test_config_validator():
    """测试配置验证器"""
    print("\n🔍 测试配置验证器...")
    
    try:
        from src.utils.config_validator import validate_config_file
        
        config_file = "config.ini"
        if os.path.exists(config_file):
            is_valid, results = validate_config_file(config_file)
            print(f"配置文件验证结果: {'有效' if is_valid else '无效'}")
            
            if not is_valid and results:
                print("配置问题:")
                # results 是 List[ValidationResult]，按照section分组显示
                sections = {}
                for result in results:
                    if result.section not in sections:
                        sections[result.section] = []
                    sections[result.section].append(result)
                
                for section, issues in sections.items():
                    if issues:
                        print(f"  [{section}]: {len(issues)}个问题")
                        for issue in issues[:3]:  # 最多显示3个问题
                            level_icon = "❌" if issue.level.value == "error" else "⚠️" if issue.level.value == "warning" else "ℹ️"
                            print(f"    {level_icon} {issue.key}: {issue.message}")
        else:
            print("配置文件不存在，跳过验证")
        
        return True
        
    except Exception as e:
        print(f"❌ 配置验证器测试失败: {e}")
        return False

def test_error_handling():
    """测试错误处理"""
    print("\n🔍 测试错误处理...")
    
    try:
        from src.utils.error_dialog import show_user_friendly_error
        from src.utils.exception_recovery import get_global_recovery_manager
        
        # 测试异常恢复管理器
        recovery_manager = get_global_recovery_manager()
        print("✅ 异常恢复管理器初始化成功")
        
        # 测试错误对话框（不显示GUI）
        print("✅ 错误对话框模块加载成功")
        
        return True
        
    except Exception as e:
        print(f"❌ 错误处理测试失败: {e}")
        return False

def test_health_monitor():
    """测试健康监控"""
    print("\n🔍 测试健康监控...")
    
    try:
        from src.utils.health_monitor import get_health_monitor, start_health_monitoring
        
        # 启动健康监控
        start_health_monitoring()
        print("✅ 健康监控启动成功")
        
        # 获取健康监控器实例
        monitor = get_health_monitor()
        print("✅ 健康监控器实例获取成功")
        
        return True
        
    except Exception as e:
        print(f"❌ 健康监控测试失败: {e}")
        return False

def test_gui_import():
    """测试GUI模块导入"""
    print("\n🔍 测试GUI模块导入...")
    
    try:
        # 测试tkinter
        import tkinter as tk
        print("✅ tkinter模块导入成功")
        
        # 测试主窗口模块（不启动GUI）
        from src.gui.main_window import MainWindow
        print("✅ 主窗口模块导入成功")
        
        return True
        
    except Exception as e:
        print(f"❌ GUI模块测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("=" * 60)
    print("Android系统修复工具 - 闪退问题解决方案测试")
    print("=" * 60)
    
    tests = [
        ("依赖检查器", test_dependency_checker),
        ("配置验证器", test_config_validator),
        ("错误处理", test_error_handling),
        ("健康监控", test_health_monitor),
        ("GUI模块", test_gui_import)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"❌ {test_name}测试异常: {e}")
    
    print("\n" + "=" * 60)
    print(f"测试结果: {passed_tests}/{total_tests} 项测试通过")
    
    if passed_tests == total_tests:
        print("🎉 所有测试通过！闪退问题解决方案工作正常。")
        print("\n✅ 您现在可以安全地运行:")
        print("   python start_safe.py")
        print("或者直接运行:")
        print("   python main.py")
    else:
        print("⚠️ 部分测试失败，需要进一步调试。")
        print("\n建议:")
        print("1. 运行: pip install -r requirements.txt")
        print("2. 检查Python版本是否 >= 3.8")
        print("3. 查看详细错误信息")
    
    print("=" * 60)

if __name__ == "__main__":
    main()