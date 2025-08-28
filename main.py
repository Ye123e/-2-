#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具主程序
Author: Android Repair Tool Team
Version: 1.0.0
"""

import sys
import os
import logging
from pathlib import Path
import time

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 导入闪退修复组件
from src.utils.dependency_checker import quick_check, detailed_check
from src.utils.config_validator import validate_config_file
from src.utils.exception_recovery import get_global_recovery_manager
from src.utils.error_dialog import show_user_friendly_error
from src.utils.health_monitor import start_health_monitoring, get_health_monitor
from src.gui.main_window import MainWindow
from src.utils.logger import setup_logger
from src.config.settings import AppConfig

def startup_checks() -> bool:
    """
    执行启动时的安全检查
    
    Returns:
        True 如果所有检查通过，False 如果有关键问题
    """
    print("正在进行启动安全检查...")
    
    # 1. 快速依赖检查
    print("检查系统依赖...")
    if not quick_check():
        print("⚠️ 发现依赖问题，进行详细检查...")
        detailed_results = detailed_check()
        
        # 显示检查报告
        from src.utils.dependency_checker import DependencyChecker
        checker = DependencyChecker()
        checker.check_results = detailed_results
        
        if checker.has_critical_failures():
            print("❌ 发现关键依赖问题：")
            for result in checker.get_failed_checks():
                print(f"  - {result.name}: {result.message}")
                for suggestion in result.fix_suggestions:
                    print(f"    建议: {suggestion}")
            return False
        else:
            print("⚠️ 发现一些警告，但不影响启动")
    else:
        print("✅ 依赖检查通过")
    
    # 2. 配置文件验证
    print("验证配置文件...")
    config_file = "config.ini"
    
    if os.path.exists(config_file):
        is_valid, validation_results = validate_config_file(config_file)
        
        if not is_valid:
            print("⚠️ 配置文件存在问题，将尝试修复")
            
            # 尝试自动修复配置
            from src.utils.config_validator import ConfigValidator
            import configparser
            
            config = configparser.ConfigParser()
            config.read(config_file, encoding='utf-8')
            
            validator = ConfigValidator()
            validator.validate_config(config)
            fixed_count = validator.fix_config(config, fix_errors=True, fix_warnings=True)
            
            if fixed_count > 0:
                with open(config_file, 'w', encoding='utf-8') as f:
                    config.write(f)
                print(f"✅ 已修复 {fixed_count} 个配置问题")
            else:
                print("ℹ️ 配置问题无法自动修复，将使用默认设置")
        else:
            print("✅ 配置文件验证通过")
    else:
        print("ℹ️ 配置文件不存在，将创建默认配置")
    
    return True

def main():
    """主程序入口"""
    print("=" * 50)
    print("Android系统修复工具")
    print("版本: 1.0.0")
    print("=" * 50)
    
    try:
        # 安装全局异常恢复管理器
        recovery_manager = get_global_recovery_manager()
        
        # 执行启动检查
        if not startup_checks():
            print("\n❌ 启动检查失败，程序无法继续运行")
            print("请解决上述问题后重新启动程序")
            input("\n按 Enter 键退出...")
            sys.exit(1)
        
        print("\n正在初始化应用程序...")
        
        # 初始化配置
        config = AppConfig()
        
        # 设置增强的日志系统
        from src.utils.logger import LogConfig, create_logger_config_from_dict
        
        log_config_dict = {
            'level': config.log_level,
            'file': config.log_file,
            'max_size': config.get('logging', 'max_size', '10MB'),
            'backup_count': config.getint('logging', 'backup_count', 5),
            'enable_console': True,
            'enable_file': True,
            'enable_monitoring': True,
            'compress_backups': True
        }
        
        log_config = create_logger_config_from_dict(log_config_dict)
        logger = setup_logger(config=log_config)
        
        logger.info("=" * 50)
        logger.info("Android系统修复工具启动")
        logger.info("版本: 1.0.0")
        logger.info("=" * 50)
        
        # 启动健康监控
        print("启动系统健康监控...")
        start_health_monitoring()
        
        # 设置健康监控回调
        health_monitor = get_health_monitor()
        
        def health_alert_callback(alert):
            logger.warning(f"健康警报: {alert.message}")
            if alert.severity.value in ['critical', 'error']:
                # 对于严重警报，可以触发额外的处理
                logger.error(f"严重健康问题: {alert.metric_name} - {alert.message}")
        
        health_monitor.add_alert_callback(health_alert_callback)
        logger.info("✅ 健康监控已启动")
        
        # 启动GUI界面
        print("启动图形界面...")
        logger.info("启动GUI界面")
        
        app = MainWindow(config)
        
        # 在GUI中添加健康状态显示
        def update_health_status():
            try:
                health_status = health_monitor.get_overall_health()
                # 这里可以更新GUI中的健康状态指示器
                # app.update_health_status(health_status)
            except Exception as e:
                logger.error(f"更新健康状态失败: {e}")
        
        # 定期更新健康状态（每30秒）
        app.root.after(30000, update_health_status)
        
        print("✅ 程序启动完成")
        logger.info("程序启动完成，开始运行GUI")
        
        # 运行应用
        app.run()
        
    except Exception as e:
        # 使用异常恢复系统处理启动错误
        logger.error(f"程序启动失败: {e}", exc_info=True)
        
        try:
            # 显示用户友好的错误信息
            show_user_friendly_error(e)
        except Exception as dialog_error:
            # 如果连错误对话框都无法显示，使用基本的错误处理
            print(f"\n❌ 程序启动失败: {e}")
            print(f"错误对话框显示失败: {dialog_error}")
            print("\n请检查以下可能的原因:")
            print("1. Python版本是否 >= 3.8")
            print("2. 是否安装了所有必需的依赖包")
            print("3. 是否有足够的系统权限")
            print("4. 配置文件是否正确")
            print("\n详细错误信息请查看日志文件: logs/app.log")
            
            input("\n按 Enter 键退出...")
        
        sys.exit(1)
    
    finally:
        # 清理资源
        try:
            from src.utils.health_monitor import stop_health_monitoring
            stop_health_monitoring()
            logging.info("健康监控已停止")
        except Exception as e:
            print(f"清理健康监控时发生错误: {e}")
        
        # 显示运行统计
        try:
            from src.utils.logger import get_log_stats
            stats = get_log_stats()
            if stats:
                print(f"\n运行统计:")
                print(f"  总日志数: {stats['total_logs']}")
                print(f"  错误数: {stats['error_count']}")
                print(f"  警告数: {stats['warning_count']}")
                if stats['error_rate'] > 0:
                    print(f"  错误率: {stats['error_rate']:.2f}/分钟")
        except Exception:
            pass
        
        print("\n程序已安全退出")

if __name__ == "__main__":
    main()