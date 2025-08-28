#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MainWindow属性访问错误修复验证测试
"""

def test_mainwindow_import():
    """测试MainWindow导入"""
    try:
        from src.gui.main_window import MainWindow
        print("✓ MainWindow导入成功")
        return True
    except Exception as e:
        print(f"✗ MainWindow导入失败: {e}")
        return False

def test_config_import():
    """测试AppConfig导入"""
    try:
        from src.config.settings import AppConfig
        print("✓ AppConfig导入成功")
        return True
    except Exception as e:
        print(f"✗ AppConfig导入失败: {e}")
        return False

def test_mainwindow_instantiation():
    """测试MainWindow实例化"""
    try:
        from src.gui.main_window import MainWindow
        from src.config.settings import AppConfig
        
        config = AppConfig()
        app = MainWindow(config)
        print("✓ MainWindow实例化成功")
        return True, app
    except Exception as e:
        print(f"✗ MainWindow实例化失败: {e}")
        return False, None

def test_run_method_access():
    """测试run方法访问"""
    try:
        from src.gui.main_window import MainWindow
        from src.config.settings import AppConfig
        
        config = AppConfig()
        app = MainWindow(config)
        
        # 检查run方法是否存在
        if hasattr(app, 'run'):
            print("✓ run方法存在")
            print(f"✓ run方法类型: {type(app.run)}")
            print("✓ MainWindow属性访问错误已修复")
            return True
        else:
            print("✗ run方法不存在")
            return False
    except Exception as e:
        print(f"✗ run方法访问测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("=" * 50)
    print("MainWindow属性访问错误修复验证测试")
    print("=" * 50)
    
    tests = [
        ("导入测试", [test_mainwindow_import, test_config_import]),
        ("实例化测试", [test_mainwindow_instantiation]),
        ("run方法访问测试", [test_run_method_access])
    ]
    
    all_passed = True
    
    for test_group, test_funcs in tests:
        print(f"\n{test_group}:")
        for test_func in test_funcs:
            result = test_func()
            if isinstance(result, tuple):
                success = result[0]
            else:
                success = result
            
            if not success:
                all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ 所有测试通过 - MainWindow属性访问错误已成功修复")
    else:
        print("✗ 部分测试失败")
    print("=" * 50)

if __name__ == "__main__":
    main()