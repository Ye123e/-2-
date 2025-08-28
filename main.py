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

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.gui.main_window import MainWindow
from src.utils.logger import setup_logger
from src.config.settings import AppConfig

def main():
    """主程序入口"""
    try:
        # 初始化配置
        config = AppConfig()
        
        # 设置日志
        setup_logger(config.log_level, config.log_file)
        logger = logging.getLogger(__name__)
        
        logger.info("=" * 50)
        logger.info("Android系统修复工具启动")
        logger.info("版本: 1.0.0")
        logger.info("=" * 50)
        
        # 启动GUI界面
        app = MainWindow(config)
        app.run()
        
    except Exception as e:
        print(f"程序启动失败: {e}")
        logging.error(f"程序启动失败: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()