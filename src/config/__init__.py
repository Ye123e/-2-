#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
应用配置管理模块
负责读取和管理应用程序配置
"""

import os
import configparser
from pathlib import Path
from typing import Dict, Any

class AppConfig:
    """应用程序配置管理器"""
    
    def __init__(self, config_file: str = "config.ini"):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径
        """
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self._load_config()
        self._ensure_directories()
    
    def _load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file, encoding='utf-8')
            else:
                self._create_default_config()
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """创建默认配置"""
        self.config['app'] = {
            'name': 'Android系统修复工具',
            'version': '1.0.0',
            'author': 'Android Repair Tool Team'
        }
        
        self.config['logging'] = {
            'level': 'INFO',
            'file': 'logs/app.log',
            'max_size': '10MB',
            'backup_count': '5'
        }
        
        self.config['adb'] = {
            'timeout': '30',
            'retry_count': '3',
            'port': '5037'
        }
        
        self.config['network'] = {
            'timeout': '10',
            'retry_count': '3',
            'user_agent': 'AndroidRepairTool/1.0'
        }
        
        self.config['security'] = {
            'enable_virus_scan': 'true',
            'virus_db_path': 'data/virus_signatures',
            'quarantine_path': 'data/quarantine',
            'max_scan_size': '100MB'
        }
        
        self.config['repair'] = {
            'backup_enabled': 'true',
            'backup_path': 'backups',
            'max_backup_count': '10',
            'verify_repair': 'true'
        }
        
        self.config['ui'] = {
            'theme': 'default',
            'language': 'zh_CN',
            'window_width': '1000',
            'window_height': '700',
            'auto_connect': 'true'
        }
    
    def _ensure_directories(self):
        """确保必要的目录存在"""
        directories = [
            'logs',
            'data',
            'data/virus_signatures',
            'data/quarantine',
            'backups'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get(self, section: str, key: str, fallback: Any = None) -> str:
        """
        获取配置值
        
        Args:
            section: 配置节
            key: 配置键
            fallback: 默认值
            
        Returns:
            配置值
        """
        return self.config.get(section, key, fallback=fallback)
    
    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """获取整数配置值"""
        return self.config.getint(section, key, fallback=fallback)
    
    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """获取布尔配置值"""
        return self.config.getboolean(section, key, fallback=fallback)
    
    def set(self, section: str, key: str, value: str):
        """设置配置值"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
    
    def save(self):
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.config.write(f)
        except Exception as e:
            print(f"配置文件保存失败: {e}")
    
    # 常用配置属性
    @property
    def app_name(self) -> str:
        return self.get('app', 'name', 'Android系统修复工具')
    
    @property
    def app_version(self) -> str:
        return self.get('app', 'version', '1.0.0')
    
    @property
    def log_level(self) -> str:
        return self.get('logging', 'level', 'INFO')
    
    @property
    def log_file(self) -> str:
        return self.get('logging', 'file', 'logs/app.log')
    
    @property
    def adb_timeout(self) -> int:
        return self.getint('adb', 'timeout', 30)
    
    @property
    def adb_port(self) -> int:
        return self.getint('adb', 'port', 5037)
    
    @property
    def window_width(self) -> int:
        return self.getint('ui', 'window_width', 1000)
    
    @property
    def window_height(self) -> int:
        return self.getint('ui', 'window_height', 700)
    
    @property
    def auto_connect(self) -> bool:
        return self.getboolean('ui', 'auto_connect', True)
    
    @property
    def virus_scan_enabled(self) -> bool:
        return self.getboolean('security', 'enable_virus_scan', True)
    
    @property
    def backup_enabled(self) -> bool:
        return self.getboolean('repair', 'backup_enabled', True)