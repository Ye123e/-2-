#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具启动脚本
用于测试和启动应用程序
"""

import sys
import os
import logging
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_dependencies():
    """检查依赖项"""
    required_modules = [
        'tkinter', 'requests', 'psutil'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"缺少以下依赖模块: {', '.join(missing_modules)}")
        print("请运行: pip install -r requirements.txt")
        return False
    
    return True

def create_directories():
    """创建必要的目录"""
    directories = [
        'logs',
        'data',
        'data/virus_signatures',
        'data/system_resources',
        'data/quarantine',
        'backups',
        'cache/downloads'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("已创建必要的目录结构")

def main():
    """主函数"""
    print("=" * 60)
    print("Android系统修复工具启动器")
    print("版本: 1.0.0")
    print("=" * 60)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 创建目录
    create_directories()
    
    try:
        # 导入并启动应用
        from src.gui.main_window import MainWindow
        from src.config.settings import AppConfig
        
        # 初始化配置
        config = AppConfig()
        
        # 启动GUI应用
        print("正在启动图形界面...")
        app = MainWindow(config)
        app.run()  # type: ignore
        
    except ImportError as e:
        print(f"导入模块失败: {e}")
        print("请检查项目文件结构是否完整")
        sys.exit(1)
    except Exception as e:
        print(f"启动失败: {e}")
        logging.exception("应用启动异常")
        sys.exit(1)

if __name__ == "__main__":
    main()