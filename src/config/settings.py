#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置设置模块
提供应用程序配置管理功能
"""

import os
import configparser
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
import json

class AppConfig:
    """应用程序配置管理器"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径，如果为None则使用默认路径
        """
        self.config_file = config_file or self._get_default_config_path()
        self.config = configparser.ConfigParser()
        self._validation_errors: List[str] = []
        self._load_config()
        self._validate_config()
        self._create_directories()
    
    def _get_default_config_path(self) -> str:
        """获取默认配置文件路径"""
        project_root = Path(__file__).parent.parent.parent
        return str(project_root / "config.ini")
    
    def _load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file, encoding='utf-8')
                logging.info(f"配置文件加载成功: {self.config_file}")
            else:
                logging.warning(f"配置文件不存在: {self.config_file}")
                self._create_default_config()
        except Exception as e:
            logging.error(f"配置文件加载失败: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """创建默认配置"""
        # 应用基本信息
        self.config['app'] = {
            'name': 'Android系统修复工具',
            'version': '1.0.0',
            'author': 'Android Repair Tool Team',
            'description': '基于Python的Android设备系统修复工具'
        }
        
        # 日志配置
        self.config['logging'] = {
            'level': 'INFO',
            'file': 'logs/app.log',
            'max_size': '10MB',
            'backup_count': '5'
        }
        
        # ADB配置
        self.config['adb'] = {
            'timeout': '30',
            'retry_count': '3',
            'port': '5037',
            'adb_path': '',
            'adb_key_path': '~/.android/adbkey',
            'auto_detect_adb': 'true'
        }
        
        # 网络配置
        self.config['network'] = {
            'timeout': '10',
            'retry_count': '3',
            'user_agent': 'AndroidRepairTool/1.0'
        }
        
        # 安全配置
        self.config['security'] = {
            'enable_virus_scan': 'true',
            'virus_db_path': 'data/virus_signatures',
            'quarantine_path': 'data/quarantine',
            'max_scan_size': '100MB',
            'yara_rules_path': 'data/yara_rules',
            'auto_quarantine': 'true',
            'scan_timeout': '300'
        }
        
        # 资源扫描配置
        self.config['resource_scan'] = {
            'enable_resource_scan': 'true',
            'system_lib_paths': '/system/lib,/system/lib64,/vendor/lib',
            'framework_paths': '/system/framework',
            'system_app_paths': '/system/app,/system/priv-app',
            'resource_db_path': 'data/system_resources',
            'verify_checksums': 'true'
        }
        
        # 文件清理配置
        self.config['file_cleanup'] = {
            'enable_file_cleanup': 'true',
            'temp_paths': '/data/tmp,/cache,/data/cache',
            'log_paths': '/data/log,/data/tombstones',
            'max_file_age_days': '30',
            'max_log_size_mb': '100',
            'safe_delete': 'true',
            'backup_before_delete': 'true'
        }
        
        # 修复配置
        self.config['repair'] = {
            'backup_enabled': 'true',
            'backup_path': 'backups',
            'max_backup_count': '10',
            'verify_repair': 'true'
        }
        
        # UI配置
        self.config['ui'] = {
            'theme': 'default',
            'language': 'zh_CN',
            'window_width': '1000',
            'window_height': '700',
            'auto_connect': 'true'
        }
        
        self.save_config()
    
    def _create_directories(self):
        """创建必要的目录"""
        directories = [
            self.log_dir,
            self.data_dir,
            self.backup_dir,
            self.quarantine_dir,
            self.virus_db_dir,
            self.resource_db_dir
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get(self, section: str, key: str, fallback: Any = None) -> str:
        """获取配置值"""
        try:
            return self.config.get(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """获取整数配置值"""
        try:
            return self.config.getint(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback
    
    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """获取布尔配置值"""
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback
    
    def set(self, section: str, key: str, value: str):
        """设置配置值"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
    
    def save_config(self):
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logging.info(f"配置文件保存成功: {self.config_file}")
        except Exception as e:
            logging.error(f"配置文件保存失败: {e}")
    
    # 便捷属性访问器
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
    def log_dir(self) -> str:
        return os.path.dirname(self.log_file)
    
    @property
    def data_dir(self) -> str:
        return 'data'
    
    @property
    def backup_dir(self) -> str:
        return self.get('repair', 'backup_path', 'backups')
    
    @property
    def quarantine_dir(self) -> str:
        return self.get('security', 'quarantine_path', 'data/quarantine')
    
    @property
    def virus_db_dir(self) -> str:
        return self.get('security', 'virus_db_path', 'data/virus_signatures')
    
    @property
    def resource_db_dir(self) -> str:
        return self.get('resource_scan', 'resource_db_path', 'data/system_resources')
    
    @property
    def adb_timeout(self) -> int:
        return self.getint('adb', 'timeout', 30)
    
    @property
    def adb_port(self) -> int:
        return self.getint('adb', 'port', 5037)
    
    @property
    def adb_path(self) -> Optional[str]:
        """获取ADB可执行文件路径"""
        config_path = self.get('adb', 'adb_path', '')
        if config_path:
            return config_path
        
        # 如果配置中没有指定，尝试自动检测
        if self.getboolean('adb', 'auto_detect_adb', True):
            return self._detect_adb_path()
        
        return None
    
    @property
    def adb_key_path(self) -> str:
        """获取ADB密钥文件路径"""
        key_path = self.get('adb', 'adb_key_path', '~/.android/adbkey')
        return os.path.expanduser(key_path)
    
    def _detect_adb_path(self) -> Optional[str]:
        """自动检测ADB路径"""
        import shutil
        
        # 首先检查PATH中是否有adb
        adb_path = shutil.which('adb')
        if adb_path:
            logging.info(f"从 PATH 中检测到 ADB: {adb_path}")
            return adb_path
        
        # 检查常见的Android SDK安装路径
        common_paths = []
        
        if os.name == 'nt':  # Windows
            common_paths = [
                os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe'),
                os.path.expandvars(r'%PROGRAMFILES%\Android\Android Studio\bin\adb.exe'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%\Android\android-sdk\platform-tools\adb.exe'),
                r'C:\android-sdk\platform-tools\adb.exe'
            ]
        else:  # Linux/macOS
            home = os.path.expanduser('~')
            common_paths = [
                f'{home}/Android/Sdk/platform-tools/adb',
                f'{home}/Library/Android/sdk/platform-tools/adb',  # macOS
                '/opt/android-sdk/platform-tools/adb',
                '/usr/local/bin/adb'
            ]
        
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                logging.info(f"检测到 ADB 路径: {path}")
                return path
        
        # 检查环境变量ANDROID_HOME
        android_home = os.environ.get('ANDROID_HOME')
        if android_home:
            adb_path = os.path.join(android_home, 'platform-tools', 'adb')
            if os.name == 'nt':
                adb_path += '.exe'
            
            if os.path.isfile(adb_path) and os.access(adb_path, os.X_OK):
                logging.info(f"从 ANDROID_HOME 检测到 ADB: {adb_path}")
                return adb_path
        
        logging.warning("未能检测到 ADB 路径，请手动在配置中指定")
        return None
    
    def set_adb_path(self, adb_path: str) -> bool:
        """
        设置 ADB 路径
        
        Args:
            adb_path: ADB 可执行文件路径
            
        Returns:
            设置是否成功
        """
        # 验证文件是否存在且可执行
        if not os.path.isfile(adb_path):
            logging.error(f"ADB 文件不存在: {adb_path}")
            return False
        
        if not os.access(adb_path, os.X_OK):
            logging.error(f"ADB 文件不可执行: {adb_path}")
            return False
        
        # 设置配置
        self.set('adb', 'adb_path', adb_path)
        self.save_config()
        
        logging.info(f"ADB 路径已设置: {adb_path}")
        return True
    
    def validate_adb_installation(self) -> bool:
        """
        验证 ADB 安装
        
        Returns:
            ADB 是否可用
        """
        adb_path = self.adb_path
        if not adb_path:
            return False
        
        try:
            import subprocess
            result = subprocess.run(
                [adb_path, 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and 'Android Debug Bridge' in result.stdout:
                logging.info(f"ADB 验证成功: {adb_path}")
                return True
            else:
                logging.error(f"ADB 验证失败: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"ADB 验证异常: {e}")
            return False
    
    @property
    def enable_virus_scan(self) -> bool:
        return self.getboolean('security', 'enable_virus_scan', True)
    
    @property
    def enable_resource_scan(self) -> bool:
        return self.getboolean('resource_scan', 'enable_resource_scan', True)
    
    @property
    def enable_file_cleanup(self) -> bool:
        return self.getboolean('file_cleanup', 'enable_file_cleanup', True)
    
    @property
    def window_width(self) -> int:
        return self.getint('ui', 'window_width', 1000)
    
    @property
    def window_height(self) -> int:
        return self.getint('ui', 'window_height', 700)
    
    @property
    def auto_connect(self) -> bool:
        return self.getboolean('ui', 'auto_connect', True)
    
    def _validate_config(self):
        """验证配置的有效性"""
        self._validation_errors.clear()
        
        # 验证基本配置
        self._validate_basic_config()
        
        # 验证ADB配置
        self._validate_adb_config()
        
        # 验证路径配置
        self._validate_path_config()
        
        # 验证网络配置
        self._validate_network_config()
        
        # 验证UI配置
        self._validate_ui_config()
        
        if self._validation_errors:
            error_msg = "配置验证失败:\n" + "\n".join(self._validation_errors)
            logging.warning(error_msg)
        else:
            logging.info("配置验证通过")
    
    def _validate_basic_config(self):
        """验证基本配置"""
        required_sections = ['app', 'logging', 'adb', 'ui']
        
        for section in required_sections:
            if not self.config.has_section(section):
                self._validation_errors.append(f"缺失必需的配置节: {section}")
        
        # 验证应用信息
        if self.config.has_section('app'):
            if not self.get('app', 'name'):
                self._validation_errors.append("应用名称不能为空")
            
            version = self.get('app', 'version')
            if not version or not self._is_valid_version(version):
                self._validation_errors.append(f"无效的版本号: {version}")
    
    def _validate_adb_config(self):
        """验证ADB配置"""
        if not self.config.has_section('adb'):
            return
        
        timeout = self.adb_timeout
        if timeout <= 0 or timeout > 300:
            self._validation_errors.append(f"ADB超时时间不合理: {timeout}秒")
        
        port = self.adb_port
        if port < 1024 or port > 65535:
            self._validation_errors.append(f"ADB端口不合理: {port}")
        
        retry_count = self.getint('adb', 'retry_count', 3)
        if retry_count < 0 or retry_count > 10:
            self._validation_errors.append(f"ADB重试次数不合理: {retry_count}")
    
    def _validate_path_config(self):
        """验证路径配置"""
        # 检查日志目录可写性
        try:
            log_dir = Path(self.log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # 测试写入权限
            test_file = log_dir / ".test_write"
            test_file.write_text("test")
            test_file.unlink()
        except Exception as e:
            self._validation_errors.append(f"日志目录不可写: {self.log_dir} - {e}")
        
        # 检查备份目录
        try:
            backup_dir = Path(self.backup_dir)
            backup_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self._validation_errors.append(f"备份目录创建失败: {self.backup_dir} - {e}")
    
    def _validate_network_config(self):
        """验证网络配置"""
        if not self.config.has_section('network'):
            return
        
        timeout = self.getint('network', 'timeout', 10)
        if timeout <= 0 or timeout > 60:
            self._validation_errors.append(f"网络超时时间不合理: {timeout}秒")
        
        user_agent = self.get('network', 'user_agent')
        if not user_agent or len(user_agent) > 200:
            self._validation_errors.append(f"User-Agent不合理: {user_agent}")
    
    def _validate_ui_config(self):
        """验证UI配置"""
        if not self.config.has_section('ui'):
            return
        
        width = self.window_width
        height = self.window_height
        
        if width < 800 or width > 2560:
            self._validation_errors.append(f"窗口宽度不合理: {width}")
        
        if height < 600 or height > 1440:
            self._validation_errors.append(f"窗口高度不合理: {height}")
        
        language = self.get('ui', 'language', 'zh_CN')
        valid_languages = ['zh_CN', 'en_US', 'zh_TW']
        if language not in valid_languages:
            self._validation_errors.append(f"不支持的语言: {language}")
    
    def _is_valid_version(self, version: str) -> bool:
        """验证版本号格式"""
        import re
        pattern = r'^\d+\.\d+\.\d+$'
        return bool(re.match(pattern, version))
    
    def get_validation_errors(self) -> List[str]:
        """获取配置验证错误列表"""
        return self._validation_errors.copy()
    
    def is_valid(self) -> bool:
        """检查配置是否有效"""
        return len(self._validation_errors) == 0
    
    def export_config(self, export_path: str) -> bool:
        """
        导出配置到JSON文件
        
        Args:
            export_path: 导出文件路径
            
        Returns:
            导出是否成功
        """
        try:
            config_dict = {}
            
            for section_name in self.config.sections():
                config_dict[section_name] = dict(self.config.items(section_name))
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, ensure_ascii=False, indent=2)
            
            logging.info(f"配置导出成功: {export_path}")
            return True
            
        except Exception as e:
            logging.error(f"配置导出失败: {e}")
            return False
    
    def reset_to_default(self):
        """重置为默认配置"""
        logging.info("重置配置为默认值")
        self.config.clear()
        self._create_default_config()
        self._validate_config()

# 导出主要配置类
__all__ = ['AppConfig']