#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件验证和错误恢复机制（精简版）
"""

import os
import configparser
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

@dataclass
class ConfigValidationResult:
    """配置验证结果"""
    is_valid: bool = False
    errors: List[str] = None
    warnings: List[str] = None
    fixed_issues: List[str] = None
    
    def __post_init__(self):
        for field in ['errors', 'warnings', 'fixed_issues']:
            if getattr(self, field) is None:
                setattr(self, field, [])

class ConfigValidator:
    """配置文件验证器"""
    
    def __init__(self, config_file: str):
        self.config_file = Path(config_file)
        self.logger = logging.getLogger(__name__)
        self.backup_dir = self.config_file.parent / "config_backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # 必需的配置结构
        self.required_config = {
            'app': {'name', 'version', 'author'},
            'logging': {'level', 'file', 'max_size', 'backup_count'},
            'adb': {'timeout', 'retry_count', 'port', 'adb_path'},
            'network': {'timeout', 'retry_count', 'user_agent'},
            'security': {'enable_virus_scan', 'virus_db_path', 'quarantine_path'},
            'ui': {'theme', 'language', 'window_width', 'window_height', 'auto_connect'}
        }
        
        # 默认配置值
        self.default_values = {
            'app': {
                'name': 'Android系统修复工具',
                'version': '1.0.0',
                'author': 'Android Repair Tool Team'
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/app.log',
                'max_size': '10MB',
                'backup_count': '5'
            },
            'adb': {
                'timeout': '30',
                'retry_count': '3',
                'port': '5037',
                'adb_path': ''
            },
            'network': {
                'timeout': '10',
                'retry_count': '3',
                'user_agent': 'AndroidRepairTool/1.0'
            },
            'security': {
                'enable_virus_scan': 'true',
                'virus_db_path': 'data/virus_signatures',
                'quarantine_path': 'data/quarantine'
            },
            'ui': {
                'theme': 'default',
                'language': 'zh_CN',
                'window_width': '1000',
                'window_height': '700',
                'auto_connect': 'true'
            }
        }
    
    def backup_config(self) -> str:
        """备份配置文件"""
        if not self.config_file.exists():
            return ""
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"config_{timestamp}.ini"
            shutil.copy2(self.config_file, backup_path)
            self.logger.info(f"配置文件已备份到: {backup_path}")
            return str(backup_path)
        except Exception as e:
            self.logger.error(f"配置文件备份失败: {e}")
            return ""
    
    def validate_config(self) -> ConfigValidationResult:
        """验证配置文件"""
        result = ConfigValidationResult()
        
        if not self.config_file.exists():
            result.errors.append(f"配置文件不存在: {self.config_file}")
            return result
        
        try:
            config = configparser.ConfigParser()
            config.read(self.config_file, encoding='utf-8')
            
            # 检查必需的节和键
            for section_name, required_keys in self.required_config.items():
                if not config.has_section(section_name):
                    result.errors.append(f"缺少配置节: {section_name}")
                    continue
                
                for key_name in required_keys:
                    if not config.has_option(section_name, key_name):
                        result.errors.append(f"缺少配置项: {section_name}.{key_name}")
            
            # 验证特定值
            if config.has_option('logging', 'level'):
                level = config.get('logging', 'level').upper()
                if level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                    result.warnings.append(f"无效的日志级别: {level}")
            
            if config.has_option('adb', 'port'):
                try:
                    port = int(config.get('adb', 'port'))
                    if not (1024 <= port <= 65535):
                        result.warnings.append(f"ADB端口超出范围: {port}")
                except ValueError:
                    result.warnings.append("ADB端口不是有效数字")
            
            result.is_valid = not result.errors
            
        except Exception as e:
            result.errors.append(f"配置文件验证异常: {str(e)}")
        
        return result
    
    def auto_fix_config(self) -> ConfigValidationResult:
        """自动修复配置文件"""
        # 备份当前配置
        backup_path = self.backup_config()
        
        try:
            config = configparser.ConfigParser()
            if self.config_file.exists():
                config.read(self.config_file, encoding='utf-8')
            
            result = ConfigValidationResult()
            
            # 添加缺失的节和键
            for section_name, keys in self.required_config.items():
                if not config.has_section(section_name):
                    config.add_section(section_name)
                    result.fixed_issues.append(f"添加配置节: {section_name}")
                
                for key_name in keys:
                    if not config.has_option(section_name, key_name):
                        default_value = self.default_values[section_name][key_name]
                        config.set(section_name, key_name, default_value)
                        result.fixed_issues.append(f"添加配置项: {section_name}.{key_name} = {default_value}")
            
            # 保存修复后的配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.logger.info(f"配置文件修复完成，修复了 {len(result.fixed_issues)} 个问题")
            
            # 重新验证
            final_result = self.validate_config()
            final_result.fixed_issues = result.fixed_issues
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"配置文件修复失败: {e}")
            # 恢复备份
            if backup_path and Path(backup_path).exists():
                shutil.copy2(backup_path, self.config_file)
            
            result = ConfigValidationResult()
            result.errors.append(f"修复失败: {str(e)}")
            return result
    
    def create_default_config(self) -> bool:
        """创建默认配置文件"""
        try:
            config = configparser.ConfigParser()
            
            for section_name, section_values in self.default_values.items():
                config.add_section(section_name)
                for key, value in section_values.items():
                    config.set(section_name, key, value)
            
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                f.write("# Android系统修复工具配置文件\n")
                f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                config.write(f)
            
            self.logger.info(f"默认配置文件已创建: {self.config_file}")
            return True
        except Exception as e:
            self.logger.error(f"创建默认配置文件失败: {e}")
            return False
    
    def print_validation_report(self, result: ConfigValidationResult):
        """打印验证报告"""
        print(f"\n⚙️  配置文件验证报告")
        print("=" * 50)
        
        status = "✅ 通过" if result.is_valid else "❌ 失败"
        print(f"验证状态: {status}")
        
        if result.errors:
            print(f"\n🔴 错误 ({len(result.errors)}个):")
            for i, error in enumerate(result.errors, 1):
                print(f"  {i}. {error}")
        
        if result.warnings:
            print(f"\n🟡 警告 ({len(result.warnings)}个):")
            for i, warning in enumerate(result.warnings, 1):
                print(f"  {i}. {warning}")
        
        if result.fixed_issues:
            print(f"\n🔧 已修复 ({len(result.fixed_issues)}个):")
            for i, fix in enumerate(result.fixed_issues, 1):
                print(f"  {i}. {fix}")

def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description="配置文件验证工具")
    parser.add_argument("config_file", nargs='?', default="config.ini")
    parser.add_argument("--validate", action="store_true", help="验证配置")
    parser.add_argument("--fix", action="store_true", help="自动修复")
    parser.add_argument("--create", action="store_true", help="创建默认配置")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    validator = ConfigValidator(args.config_file)
    
    if args.create:
        return 0 if validator.create_default_config() else 1
    
    if args.fix:
        result = validator.auto_fix_config()
        validator.print_validation_report(result)
        return 0 if result.is_valid else 1
    
    if args.validate:
        result = validator.validate_config()
        validator.print_validation_report(result)
        return 0 if result.is_valid else 1
    
    # 默认验证
    result = validator.validate_config()
    validator.print_validation_report(result)
    return 0 if result.is_valid else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())