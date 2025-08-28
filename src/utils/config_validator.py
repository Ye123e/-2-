#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置验证器模块
增强配置文件验证，防止配置错误导致的闪退问题
"""

import os
import re
import configparser
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum

class ValidationLevel(Enum):
    """验证级别"""
    ERROR = "error"      # 错误，会导致应用无法运行
    WARNING = "warning"  # 警告，可能影响功能
    INFO = "info"       # 信息，建议修改

@dataclass
class ValidationResult:
    """验证结果"""
    section: str
    key: str
    level: ValidationLevel
    message: str
    current_value: Any = None
    expected_value: Any = None
    fix_action: str = ""
    
class ConfigValidator:
    """配置验证器"""
    
    def __init__(self):
        """初始化配置验证器"""
        self.logger = logging.getLogger(__name__)
        self.validation_results: List[ValidationResult] = []
        
        # 定义验证规则
        self._define_validation_rules()
    
    def _define_validation_rules(self):
        """定义验证规则"""
        self.validation_rules = {
            'app': {
                'name': {
                    'required': True,
                    'type': str,
                    'min_length': 1,
                    'max_length': 100,
                    'default': 'Android系统修复工具'
                },
                'version': {
                    'required': True,
                    'type': str,
                    'pattern': r'^\d+\.\d+\.\d+$',
                    'default': '1.0.0'
                },
                'author': {
                    'required': False,
                    'type': str,
                    'default': 'Android Repair Tool Team'
                }
            },
            'logging': {
                'level': {
                    'required': True,
                    'type': str,
                    'choices': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                    'default': 'INFO'
                },
                'file': {
                    'required': True,
                    'type': str,
                    'path_type': 'file',
                    'default': 'logs/app.log'
                },
                'max_size': {
                    'required': False,
                    'type': str,
                    'pattern': r'^\d+[KMG]?B$',
                    'default': '10MB'
                },
                'backup_count': {
                    'required': False,
                    'type': int,
                    'min_value': 0,
                    'max_value': 100,
                    'default': 5
                }
            },
            'adb': {
                'timeout': {
                    'required': True,
                    'type': int,
                    'min_value': 5,
                    'max_value': 300,
                    'default': 30
                },
                'retry_count': {
                    'required': False,
                    'type': int,
                    'min_value': 0,
                    'max_value': 10,
                    'default': 3
                },
                'port': {
                    'required': True,
                    'type': int,
                    'min_value': 1024,
                    'max_value': 65535,
                    'default': 5037
                },
                'adb_path': {
                    'required': False,
                    'type': str,
                    'path_type': 'executable',
                    'default': ''
                },
                'auto_detect_adb': {
                    'required': False,
                    'type': bool,
                    'default': True
                }
            },
            'network': {
                'timeout': {
                    'required': False,
                    'type': int,
                    'min_value': 1,
                    'max_value': 60,
                    'default': 10
                },
                'retry_count': {
                    'required': False,
                    'type': int,
                    'min_value': 0,
                    'max_value': 10,
                    'default': 3
                },
                'user_agent': {
                    'required': False,
                    'type': str,
                    'max_length': 200,
                    'default': 'AndroidRepairTool/1.0'
                }
            },
            'security': {
                'enable_virus_scan': {
                    'required': False,
                    'type': bool,
                    'default': True
                },
                'virus_db_path': {
                    'required': False,
                    'type': str,
                    'path_type': 'directory',
                    'default': 'data/virus_signatures'
                },
                'quarantine_path': {
                    'required': False,
                    'type': str,
                    'path_type': 'directory',
                    'default': 'data/quarantine'
                },
                'max_scan_size': {
                    'required': False,
                    'type': str,
                    'pattern': r'^\d+[KMG]?B$',
                    'default': '100MB'
                },
                'auto_quarantine': {
                    'required': False,
                    'type': bool,
                    'default': True
                },
                'scan_timeout': {
                    'required': False,
                    'type': int,
                    'min_value': 30,
                    'max_value': 3600,
                    'default': 300
                }
            },
            'ui': {
                'theme': {
                    'required': False,
                    'type': str,
                    'choices': ['default', 'dark', 'light'],
                    'default': 'default'
                },
                'language': {
                    'required': False,
                    'type': str,
                    'choices': ['zh_CN', 'en_US', 'zh_TW'],
                    'default': 'zh_CN'
                },
                'window_width': {
                    'required': False,
                    'type': int,
                    'min_value': 800,
                    'max_value': 2560,
                    'default': 1000
                },
                'window_height': {
                    'required': False,
                    'type': int,
                    'min_value': 600,
                    'max_value': 1440,
                    'default': 700
                },
                'auto_connect': {
                    'required': False,
                    'type': bool,
                    'default': True
                }
            },
            'repair': {
                'backup_enabled': {
                    'required': False,
                    'type': bool,
                    'default': True
                },
                'backup_path': {
                    'required': False,
                    'type': str,
                    'path_type': 'directory',
                    'default': 'backups'
                },
                'max_backup_count': {
                    'required': False,
                    'type': int,
                    'min_value': 1,
                    'max_value': 100,
                    'default': 10
                },
                'verify_repair': {
                    'required': False,
                    'type': bool,
                    'default': True
                }
            }
        }
    
    def validate_config(self, config: configparser.ConfigParser) -> List[ValidationResult]:
        """
        验证配置文件
        
        Args:
            config: 配置对象
            
        Returns:
            验证结果列表
        """
        self.validation_results.clear()
        
        # 验证所有定义的规则
        for section_name, section_rules in self.validation_rules.items():
            self._validate_section(config, section_name, section_rules)
        
        # 检查未知的配置项
        self._check_unknown_sections(config)
        
        return self.validation_results
    
    def _validate_section(self, config: configparser.ConfigParser, 
                         section_name: str, section_rules: Dict[str, Any]):
        """验证配置节"""
        # 检查配置节是否存在
        if not config.has_section(section_name):
            self.validation_results.append(ValidationResult(
                section=section_name,
                key="",
                level=ValidationLevel.WARNING,
                message=f"配置节 [{section_name}] 不存在",
                fix_action="将创建默认配置节"
            ))
            return
        
        # 验证每个配置项
        for key, rules in section_rules.items():
            self._validate_key(config, section_name, key, rules)
    
    def _validate_key(self, config: configparser.ConfigParser,
                     section_name: str, key: str, rules: Dict[str, Any]):
        """验证配置项"""
        try:
            # 检查是否存在
            if not config.has_option(section_name, key):
                if rules.get('required', False):
                    self.validation_results.append(ValidationResult(
                        section=section_name,
                        key=key,
                        level=ValidationLevel.ERROR,
                        message=f"必需配置项 {key} 不存在",
                        expected_value=rules.get('default'),
                        fix_action="将设置为默认值"
                    ))
                else:
                    self.validation_results.append(ValidationResult(
                        section=section_name,
                        key=key,
                        level=ValidationLevel.INFO,
                        message=f"可选配置项 {key} 不存在",
                        expected_value=rules.get('default'),
                        fix_action="将设置为默认值"
                    ))
                return
            
            # 获取值
            raw_value = config.get(section_name, key)
            
            # 类型转换和验证
            if rules['type'] == int:
                value = self._validate_int_value(section_name, key, raw_value, rules)
            elif rules['type'] == bool:
                value = self._validate_bool_value(section_name, key, raw_value, rules)
            elif rules['type'] == str:
                value = self._validate_string_value(section_name, key, raw_value, rules)
            else:
                value = raw_value
            
            # 额外验证
            self._validate_additional_rules(section_name, key, value, rules)
            
        except Exception as e:
            self.validation_results.append(ValidationResult(
                section=section_name,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"配置项验证异常: {e}",
                current_value=config.get(section_name, key, fallback=None),
                fix_action="将重置为默认值"
            ))
    
    def _validate_int_value(self, section: str, key: str, 
                           raw_value: str, rules: Dict[str, Any]) -> int:
        """验证整数值"""
        try:
            value = int(raw_value)
            
            # 检查范围
            min_val = rules.get('min_value')
            max_val = rules.get('max_value')
            
            if min_val is not None and value < min_val:
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"值 {value} 小于最小值 {min_val}",
                    current_value=value,
                    expected_value=min_val,
                    fix_action=f"将调整为最小值 {min_val}"
                ))
            
            if max_val is not None and value > max_val:
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"值 {value} 大于最大值 {max_val}",
                    current_value=value,
                    expected_value=max_val,
                    fix_action=f"将调整为最大值 {max_val}"
                ))
            
            return value
            
        except ValueError:
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"无法将 '{raw_value}' 转换为整数",
                current_value=raw_value,
                expected_value=rules.get('default'),
                fix_action="将设置为默认值"
            ))
            return rules.get('default', 0)
    
    def _validate_bool_value(self, section: str, key: str,
                            raw_value: str, rules: Dict[str, Any]) -> bool:
        """验证布尔值"""
        # 常见的布尔值表示
        true_values = {'true', 'yes', '1', 'on', 'enabled'}
        false_values = {'false', 'no', '0', 'off', 'disabled'}
        
        lower_value = raw_value.lower().strip()
        
        if lower_value in true_values:
            return True
        elif lower_value in false_values:
            return False
        else:
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"无法将 '{raw_value}' 识别为布尔值",
                current_value=raw_value,
                expected_value=rules.get('default'),
                fix_action="将设置为默认值"
            ))
            return rules.get('default', False)
    
    def _validate_string_value(self, section: str, key: str,
                              raw_value: str, rules: Dict[str, Any]) -> str:
        """验证字符串值"""
        value = raw_value.strip()
        
        # 检查长度
        min_length = rules.get('min_length')
        max_length = rules.get('max_length')
        
        if min_length is not None and len(value) < min_length:
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"字符串长度 {len(value)} 小于最小长度 {min_length}",
                current_value=value,
                expected_value=rules.get('default'),
                fix_action="将设置为默认值"
            ))
        
        if max_length is not None and len(value) > max_length:
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.WARNING,
                message=f"字符串长度 {len(value)} 大于最大长度 {max_length}",
                current_value=value,
                fix_action=f"将截断到 {max_length} 个字符"
            ))
        
        # 检查正则模式
        pattern = rules.get('pattern')
        if pattern and not re.match(pattern, value):
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"值 '{value}' 不匹配预期格式",
                current_value=value,
                expected_value=rules.get('default'),
                fix_action="将设置为默认值"
            ))
        
        # 检查选择列表
        choices = rules.get('choices')
        if choices and value not in choices:
            self.validation_results.append(ValidationResult(
                section=section,
                key=key,
                level=ValidationLevel.ERROR,
                message=f"值 '{value}' 不在允许的选择中: {choices}",
                current_value=value,
                expected_value=rules.get('default'),
                fix_action="将设置为默认值"
            ))
        
        return value
    
    def _validate_additional_rules(self, section: str, key: str,
                                  value: Any, rules: Dict[str, Any]):
        """验证额外规则"""
        # 路径验证
        path_type = rules.get('path_type')
        if path_type and isinstance(value, str) and value:
            self._validate_path(section, key, value, path_type)
    
    def _validate_path(self, section: str, key: str, path: str, path_type: str):
        """验证路径"""
        path_obj = Path(path)
        
        if path_type == 'file':
            # 检查文件是否存在
            if not path_obj.exists():
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.INFO,
                    message=f"文件路径 '{path}' 不存在",
                    current_value=path,
                    fix_action="如果需要，将自动创建"
                ))
            elif not path_obj.is_file():
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"路径 '{path}' 不是文件",
                    current_value=path,
                    fix_action="请检查路径配置"
                ))
        
        elif path_type == 'directory':
            # 检查目录是否存在
            if not path_obj.exists():
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.INFO,
                    message=f"目录路径 '{path}' 不存在",
                    current_value=path,
                    fix_action="将自动创建目录"
                ))
            elif not path_obj.is_dir():
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"路径 '{path}' 不是目录",
                    current_value=path,
                    fix_action="请检查路径配置"
                ))
        
        elif path_type == 'executable':
            # 检查可执行文件
            if path and not path_obj.exists():
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"可执行文件 '{path}' 不存在",
                    current_value=path,
                    fix_action="请检查程序安装路径"
                ))
            elif path and path_obj.exists() and not os.access(path, os.X_OK):
                self.validation_results.append(ValidationResult(
                    section=section,
                    key=key,
                    level=ValidationLevel.WARNING,
                    message=f"文件 '{path}' 不可执行",
                    current_value=path,
                    fix_action="请检查文件权限"
                ))
    
    def _check_unknown_sections(self, config: configparser.ConfigParser):
        """检查未知的配置节"""
        known_sections = set(self.validation_rules.keys())
        actual_sections = set(config.sections())
        
        unknown_sections = actual_sections - known_sections
        
        for section in unknown_sections:
            self.validation_results.append(ValidationResult(
                section=section,
                key="",
                level=ValidationLevel.INFO,
                message=f"未知的配置节 [{section}]",
                fix_action="可以保留或删除"
            ))
    
    def fix_config(self, config: configparser.ConfigParser,
                   fix_errors: bool = True, fix_warnings: bool = False) -> int:
        """
        自动修复配置
        
        Args:
            config: 配置对象
            fix_errors: 是否修复错误
            fix_warnings: 是否修复警告
            
        Returns:
            修复的问题数量
        """
        fixed_count = 0
        
        for result in self.validation_results:
            should_fix = (
                (fix_errors and result.level == ValidationLevel.ERROR) or
                (fix_warnings and result.level == ValidationLevel.WARNING)
            )
            
            if not should_fix:
                continue
            
            # 确保配置节存在
            if not config.has_section(result.section):
                config.add_section(result.section)
            
            # 设置默认值
            if result.expected_value is not None:
                config.set(result.section, result.key, str(result.expected_value))
                fixed_count += 1
                self.logger.info(f"修复配置: [{result.section}]{result.key} = {result.expected_value}")
        
        return fixed_count
    
    def create_default_config(self) -> configparser.ConfigParser:
        """创建默认配置"""
        config = configparser.ConfigParser()
        
        for section_name, section_rules in self.validation_rules.items():
            config.add_section(section_name)
            
            for key, rules in section_rules.items():
                default_value = rules.get('default')
                if default_value is not None:
                    config.set(section_name, key, str(default_value))
        
        return config
    
    def get_validation_summary(self) -> Dict[str, int]:
        """获取验证结果摘要"""
        summary = {
            'total': len(self.validation_results),
            'errors': 0,
            'warnings': 0,
            'info': 0
        }
        
        for result in self.validation_results:
            if result.level == ValidationLevel.ERROR:
                summary['errors'] += 1
            elif result.level == ValidationLevel.WARNING:
                summary['warnings'] += 1
            elif result.level == ValidationLevel.INFO:
                summary['info'] += 1
        
        return summary
    
    def generate_validation_report(self) -> str:
        """生成验证报告"""
        lines = []
        lines.append("=" * 60)
        lines.append("配置验证报告")
        lines.append("=" * 60)
        lines.append("")
        
        # 摘要
        summary = self.get_validation_summary()
        lines.append(f"验证结果摘要:")
        lines.append(f"  总计: {summary['total']} 项")
        lines.append(f"  错误: {summary['errors']} 项")
        lines.append(f"  警告: {summary['warnings']} 项")
        lines.append(f"  信息: {summary['info']} 项")
        lines.append("")
        
        # 按级别分组显示
        for level in [ValidationLevel.ERROR, ValidationLevel.WARNING, ValidationLevel.INFO]:
            level_results = [r for r in self.validation_results if r.level == level]
            
            if level_results:
                level_name = {
                    ValidationLevel.ERROR: "错误",
                    ValidationLevel.WARNING: "警告",
                    ValidationLevel.INFO: "信息"
                }[level]
                
                lines.append(f"{level_name}项目:")
                lines.append("-" * 30)
                
                for result in level_results:
                    location = f"[{result.section}]"
                    if result.key:
                        location += f".{result.key}"
                    
                    lines.append(f"  {location}: {result.message}")
                    
                    if result.current_value is not None:
                        lines.append(f"    当前值: {result.current_value}")
                    
                    if result.expected_value is not None:
                        lines.append(f"    期望值: {result.expected_value}")
                    
                    if result.fix_action:
                        lines.append(f"    修复动作: {result.fix_action}")
                    
                    lines.append("")
        
        return "\n".join(lines)

# 便捷函数
def validate_config_file(config_file_path: str) -> Tuple[bool, List[ValidationResult]]:
    """
    验证配置文件
    
    Args:
        config_file_path: 配置文件路径
        
    Returns:
        (是否有错误, 验证结果列表)
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_file_path, encoding='utf-8')
        
        validator = ConfigValidator()
        results = validator.validate_config(config)
        
        has_errors = any(r.level == ValidationLevel.ERROR for r in results)
        return not has_errors, results
        
    except Exception as e:
        error_result = ValidationResult(
            section="file",
            key="",
            level=ValidationLevel.ERROR,
            message=f"配置文件读取失败: {e}",
            fix_action="检查文件格式和权限"
        )
        return False, [error_result]

__all__ = ['ConfigValidator', 'ValidationLevel', 'ValidationResult', 'validate_config_file']