#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
依赖检查模块
用于检查运行环境、依赖包、工具等，防止闪退问题
"""

import sys
import os
import shutil
import subprocess
import importlib
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

class CheckStatus(Enum):
    """检查状态枚举"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"

@dataclass
class CheckResult:
    """检查结果数据类"""
    name: str
    status: CheckStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    fix_suggestions: List[str] = field(default_factory=list)
    error: Optional[Exception] = None

class DependencyChecker:
    """依赖检查器"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化依赖检查器
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.check_results: Dict[str, CheckResult] = {}
        
        # 必需的Python版本
        self.min_python_version = (3, 8, 0)
        
        # 核心依赖包列表
        self.core_packages = [
            ('tkinter', '内置GUI框架'),
            ('threading', '内置多线程模块'),
            ('configparser', '内置配置解析模块'),
            ('pathlib', '内置路径处理模块'),
            ('logging', '内置日志模块'),
            ('subprocess', '内置进程管理模块'),
            ('json', '内置JSON处理模块')
        ]
        
        # 第三方依赖包列表
        self.third_party_packages = [
            ('adb_shell', 'ADB Shell连接'),
            ('requests', 'HTTP请求库'),
            ('psutil', '系统进程监控'),
            ('yara', 'YARA规则引擎'),
            ('PIL', 'Python图像库'),
            ('watchdog', '文件系统监控'),
            ('cryptography', '加密库')
        ]
        
        # 可选依赖包
        self.optional_packages = [
            ('coloredlogs', '彩色日志输出'),
            ('py7zr', '7z压缩支持'),
            ('send2trash', '安全删除文件'),
            ('netifaces', '网络接口信息')
        ]
        
        # 必需目录列表
        self.required_directories = [
            'logs',
            'data',
            'backups',
            'data/quarantine',
            'data/virus_signatures',
            'data/system_resources'
        ]
    
    def check_all(self) -> Dict[str, CheckResult]:
        """
        执行全面的依赖检查
        
        Returns:
            检查结果字典
        """
        self.logger.info("开始执行系统依赖检查...")
        
        # 清空之前的结果
        self.check_results.clear()
        
        # 执行各项检查
        self._check_python_version()
        self._check_core_packages()
        self._check_third_party_packages()
        self._check_optional_packages()
        self._check_adb_availability()
        self._check_required_directories()
        self._check_file_permissions()
        self._check_system_resources()
        self._check_network_connectivity()
        
        # 生成总结
        self._generate_summary()
        
        self.logger.info("依赖检查完成")
        return self.check_results
    
    def _check_python_version(self) -> None:
        """检查Python版本"""
        try:
            current_version = sys.version_info
            version_tuple = (current_version.major, current_version.minor, current_version.micro)
            version_str = f"{current_version.major}.{current_version.minor}.{current_version.micro}"
            
            if version_tuple >= self.min_python_version:
                self.check_results['python_version'] = CheckResult(
                    name="Python版本",
                    status=CheckStatus.PASSED,
                    message=f"Python版本检查通过: {version_str}",
                    details={
                        'current_version': version_str,
                        'required_version': f"{self.min_python_version[0]}.{self.min_python_version[1]}.{self.min_python_version[2]}",
                        'executable': sys.executable
                    }
                )
            else:
                min_version_str = f"{self.min_python_version[0]}.{self.min_python_version[1]}.{self.min_python_version[2]}"
                self.check_results['python_version'] = CheckResult(
                    name="Python版本",
                    status=CheckStatus.FAILED,
                    message=f"Python版本过低: {version_str}, 需要 >= {min_version_str}",
                    details={
                        'current_version': version_str,
                        'required_version': min_version_str,
                        'executable': sys.executable
                    },
                    fix_suggestions=[
                        f"请升级Python到{min_version_str}或更高版本",
                        "建议从 https://www.python.org/downloads/ 下载最新版本",
                        "升级后重新安装项目依赖包"
                    ]
                )
                
        except Exception as e:
            self.check_results['python_version'] = CheckResult(
                name="Python版本",
                status=CheckStatus.FAILED,
                message=f"Python版本检查失败: {e}",
                error=e,
                fix_suggestions=["检查Python安装是否正确"]
            )
    
    def _check_core_packages(self) -> None:
        """检查核心内置包"""
        failed_packages = []
        
        for package_name, description in self.core_packages:
            try:
                importlib.import_module(package_name)
                self.logger.debug(f"核心包检查通过: {package_name}")
            except ImportError as e:
                failed_packages.append((package_name, description, str(e)))
                self.logger.error(f"核心包缺失: {package_name} - {e}")
        
        if not failed_packages:
            self.check_results['core_packages'] = CheckResult(
                name="核心包",
                status=CheckStatus.PASSED,
                message=f"所有核心包检查通过 ({len(self.core_packages)}个)",
                details={'checked_packages': [pkg[0] for pkg in self.core_packages]}
            )
        else:
            self.check_results['core_packages'] = CheckResult(
                name="核心包",
                status=CheckStatus.FAILED,
                message=f"发现{len(failed_packages)}个核心包缺失",
                details={'failed_packages': failed_packages},
                fix_suggestions=[
                    "这些是Python内置模块，不应该缺失",
                    "请重新安装Python",
                    "检查Python安装是否完整"
                ]
            )
    
    def _check_third_party_packages(self) -> None:
        """检查第三方依赖包"""
        failed_packages = []
        passed_packages = []
        
        for package_name, description in self.third_party_packages:
            try:
                module = importlib.import_module(package_name)
                version = getattr(module, '__version__', 'unknown')
                passed_packages.append((package_name, description, version))
                self.logger.debug(f"第三方包检查通过: {package_name} v{version}")
            except ImportError as e:
                failed_packages.append((package_name, description, str(e)))
                self.logger.warning(f"第三方包缺失: {package_name} - {e}")
        
        if not failed_packages:
            self.check_results['third_party_packages'] = CheckResult(
                name="第三方依赖包",
                status=CheckStatus.PASSED,
                message=f"所有第三方包检查通过 ({len(passed_packages)}个)",
                details={'passed_packages': passed_packages}
            )
        else:
            status = CheckStatus.FAILED if len(failed_packages) > len(passed_packages) / 2 else CheckStatus.WARNING
            
            self.check_results['third_party_packages'] = CheckResult(
                name="第三方依赖包",
                status=status,
                message=f"发现{len(failed_packages)}个第三方包缺失",
                details={
                    'failed_packages': failed_packages,
                    'passed_packages': passed_packages
                },
                fix_suggestions=[
                    "执行: pip install -r requirements.txt",
                    "或手动安装缺失的包",
                    "确保网络连接正常",
                    "如果安装失败，尝试更新pip: python -m pip install --upgrade pip"
                ]
            )
    
    def _check_optional_packages(self) -> None:
        """检查可选依赖包"""
        missing_packages = []
        available_packages = []
        
        for package_name, description in self.optional_packages:
            try:
                module = importlib.import_module(package_name)
                version = getattr(module, '__version__', 'unknown')
                available_packages.append((package_name, description, version))
                self.logger.debug(f"可选包可用: {package_name} v{version}")
            except ImportError:
                missing_packages.append((package_name, description))
                self.logger.debug(f"可选包缺失: {package_name}")
        
        if missing_packages:
            self.check_results['optional_packages'] = CheckResult(
                name="可选依赖包",
                status=CheckStatus.WARNING,
                message=f"发现{len(missing_packages)}个可选包缺失，不影响核心功能",
                details={
                    'missing_packages': missing_packages,
                    'available_packages': available_packages
                },
                fix_suggestions=[
                    "可选包不影响基本功能，可根据需要安装",
                    "执行: pip install <包名> 来安装特定包"
                ]
            )
        else:
            self.check_results['optional_packages'] = CheckResult(
                name="可选依赖包",
                status=CheckStatus.PASSED,
                message=f"所有可选包都已安装 ({len(available_packages)}个)",
                details={'available_packages': available_packages}
            )
    
    def _check_adb_availability(self) -> None:
        """检查ADB工具可用性"""
        try:
            # 首先检查PATH中是否有adb
            adb_path = shutil.which('adb')
            
            if not adb_path:
                # 检查常见安装路径
                adb_path = self._find_adb_in_common_paths()
            
            if not adb_path:
                self.check_results['adb_availability'] = CheckResult(
                    name="ADB工具",
                    status=CheckStatus.FAILED,
                    message="未找到ADB工具",
                    fix_suggestions=[
                        "安装Android SDK Platform Tools",
                        "从 https://developer.android.com/studio/releases/platform-tools 下载",
                        "或安装Android Studio",
                        "确保adb命令在PATH环境变量中"
                    ]
                )
                return
            
            # 测试ADB是否工作
            try:
                result = subprocess.run(
                    [adb_path, 'version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and 'Android Debug Bridge' in result.stdout:
                    version_info = result.stdout.strip()
                    self.check_results['adb_availability'] = CheckResult(
                        name="ADB工具",
                        status=CheckStatus.PASSED,
                        message=f"ADB工具检查通过: {adb_path}",
                        details={
                            'adb_path': adb_path,
                            'version_info': version_info
                        }
                    )
                else:
                    self.check_results['adb_availability'] = CheckResult(
                        name="ADB工具",
                        status=CheckStatus.FAILED,
                        message=f"ADB工具无法正常工作: {result.stderr}",
                        details={'adb_path': adb_path, 'error': result.stderr},
                        fix_suggestions=[
                            "重新安装Android SDK Platform Tools",
                            "检查ADB工具是否损坏",
                            "确保有足够的系统权限"
                        ]
                    )
                    
            except subprocess.TimeoutExpired:
                self.check_results['adb_availability'] = CheckResult(
                    name="ADB工具",
                    status=CheckStatus.FAILED,
                    message="ADB工具响应超时",
                    details={'adb_path': adb_path},
                    fix_suggestions=[
                        "检查系统资源是否充足",
                        "重启ADB服务: adb kill-server && adb start-server",
                        "重新安装ADB工具"
                    ]
                )
                
        except Exception as e:
            self.check_results['adb_availability'] = CheckResult(
                name="ADB工具",
                status=CheckStatus.FAILED,
                message=f"ADB检查异常: {e}",
                error=e,
                fix_suggestions=["检查ADB安装和配置"]
            )
    
    def _find_adb_in_common_paths(self) -> Optional[str]:
        """在常见路径中查找ADB"""
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
                return path
        
        # 检查ANDROID_HOME环境变量
        android_home = os.environ.get('ANDROID_HOME')
        if android_home:
            adb_path = os.path.join(android_home, 'platform-tools', 'adb')
            if os.name == 'nt':
                adb_path += '.exe'
            
            if os.path.isfile(adb_path) and os.access(adb_path, os.X_OK):
                return adb_path
        
        return None
    
    def _check_required_directories(self) -> None:
        """检查必需目录"""
        missing_dirs = []
        created_dirs = []
        
        for dir_path in self.required_directories:
            path = Path(dir_path)
            
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    created_dirs.append(str(path))
                    self.logger.info(f"创建目录: {path}")
                except Exception as e:
                    missing_dirs.append((str(path), str(e)))
                    self.logger.error(f"无法创建目录 {path}: {e}")
        
        if not missing_dirs:
            message = "所有必需目录检查通过"
            if created_dirs:
                message += f" (自动创建了{len(created_dirs)}个目录)"
            
            self.check_results['required_directories'] = CheckResult(
                name="必需目录",
                status=CheckStatus.PASSED,
                message=message,
                details={
                    'required_directories': self.required_directories,
                    'created_directories': created_dirs
                }
            )
        else:
            self.check_results['required_directories'] = CheckResult(
                name="必需目录",
                status=CheckStatus.FAILED,
                message=f"无法创建{len(missing_dirs)}个必需目录",
                details={
                    'missing_directories': missing_dirs,
                    'created_directories': created_dirs
                },
                fix_suggestions=[
                    "检查文件系统权限",
                    "确保有足够的磁盘空间",
                    "手动创建缺失的目录",
                    "以管理员权限运行程序"
                ]
            )
    
    def _check_file_permissions(self) -> None:
        """检查文件权限"""
        permission_issues = []
        
        # 检查当前目录写权限
        try:
            test_file = Path('.') / '.permission_test'
            test_file.write_text('test')
            test_file.unlink()
        except Exception as e:
            permission_issues.append(('当前目录写权限', str(e)))
        
        # 检查配置文件权限
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'a'):
                    pass
            except Exception as e:
                permission_issues.append(('配置文件写权限', str(e)))
        
        # 检查日志目录权限
        log_dir = Path('logs')
        if log_dir.exists():
            try:
                test_log = log_dir / '.log_test'
                test_log.write_text('test')
                test_log.unlink()
            except Exception as e:
                permission_issues.append(('日志目录写权限', str(e)))
        
        if not permission_issues:
            self.check_results['file_permissions'] = CheckResult(
                name="文件权限",
                status=CheckStatus.PASSED,
                message="文件权限检查通过"
            )
        else:
            self.check_results['file_permissions'] = CheckResult(
                name="文件权限",
                status=CheckStatus.WARNING,
                message=f"发现{len(permission_issues)}个权限问题",
                details={'permission_issues': permission_issues},
                fix_suggestions=[
                    "以管理员权限运行程序",
                    "检查文件夹权限设置",
                    "确保用户有读写权限"
                ]
            )
    
    def _check_system_resources(self) -> None:
        """检查系统资源"""
        try:
            import psutil
            
            # 检查内存
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024 ** 3)
            
            # 检查磁盘空间
            disk = psutil.disk_usage('.')
            disk_free_gb = disk.free / (1024 ** 3)
            
            # 检查CPU
            cpu_count = psutil.cpu_count()
            
            warnings = []
            if memory_gb < 2:
                warnings.append(f"内存较少: {memory_gb:.1f}GB，建议4GB以上")
            
            if disk_free_gb < 1:
                warnings.append(f"磁盘空间不足: {disk_free_gb:.1f}GB，建议至少1GB可用空间")
            
            if cpu_count < 2:
                warnings.append(f"CPU核心数较少: {cpu_count}核")
            
            status = CheckStatus.WARNING if warnings else CheckStatus.PASSED
            message = "系统资源检查通过" if not warnings else f"发现{len(warnings)}个资源警告"
            
            self.check_results['system_resources'] = CheckResult(
                name="系统资源",
                status=status,
                message=message,
                details={
                    'memory_gb': round(memory_gb, 1),
                    'disk_free_gb': round(disk_free_gb, 1),
                    'cpu_count': cpu_count,
                    'warnings': warnings
                },
                fix_suggestions=warnings if warnings else []
            )
            
        except ImportError:
            self.check_results['system_resources'] = CheckResult(
                name="系统资源",
                status=CheckStatus.SKIPPED,
                message="缺少psutil模块，跳过系统资源检查",
                fix_suggestions=["安装psutil模块: pip install psutil"]
            )
        except Exception as e:
            self.check_results['system_resources'] = CheckResult(
                name="系统资源",
                status=CheckStatus.FAILED,
                message=f"系统资源检查失败: {e}",
                error=e
            )
    
    def _check_network_connectivity(self) -> None:
        """检查网络连接"""
        try:
            import requests
            
            # 测试基本网络连接
            response = requests.get('https://www.google.com', timeout=5)
            
            if response.status_code == 200:
                self.check_results['network_connectivity'] = CheckResult(
                    name="网络连接",
                    status=CheckStatus.PASSED,
                    message="网络连接正常"
                )
            else:
                self.check_results['network_connectivity'] = CheckResult(
                    name="网络连接",
                    status=CheckStatus.WARNING,
                    message=f"网络连接异常: HTTP {response.status_code}",
                    fix_suggestions=["检查网络设置", "检查防火墙配置"]
                )
                
        except ImportError:
            self.check_results['network_connectivity'] = CheckResult(
                name="网络连接",
                status=CheckStatus.SKIPPED,
                message="缺少requests模块，跳过网络检查"
            )
        except Exception as e:
            self.check_results['network_connectivity'] = CheckResult(
                name="网络连接",
                status=CheckStatus.WARNING,
                message=f"网络连接检查失败: {e}",
                details={'error': str(e)},
                fix_suggestions=[
                    "检查网络连接",
                    "检查DNS设置",
                    "检查代理配置"
                ]
            )
    
    def _generate_summary(self) -> None:
        """生成检查总结"""
        total_checks = len(self.check_results)
        passed_count = sum(1 for r in self.check_results.values() if r.status == CheckStatus.PASSED)
        failed_count = sum(1 for r in self.check_results.values() if r.status == CheckStatus.FAILED)
        warning_count = sum(1 for r in self.check_results.values() if r.status == CheckStatus.WARNING)
        skipped_count = sum(1 for r in self.check_results.values() if r.status == CheckStatus.SKIPPED)
        
        overall_status = CheckStatus.PASSED
        if failed_count > 0:
            overall_status = CheckStatus.FAILED
        elif warning_count > 0:
            overall_status = CheckStatus.WARNING
        
        self.check_results['summary'] = CheckResult(
            name="检查总结",
            status=overall_status,
            message=f"总计{total_checks}项检查: {passed_count}项通过, {failed_count}项失败, {warning_count}项警告, {skipped_count}项跳过",
            details={
                'total_checks': total_checks,
                'passed_count': passed_count,
                'failed_count': failed_count,
                'warning_count': warning_count,
                'skipped_count': skipped_count
            }
        )
    
    def get_failed_checks(self) -> List[CheckResult]:
        """获取失败的检查项"""
        return [r for r in self.check_results.values() if r.status == CheckStatus.FAILED]
    
    def get_warning_checks(self) -> List[CheckResult]:
        """获取警告的检查项"""
        return [r for r in self.check_results.values() if r.status == CheckStatus.WARNING]
    
    def has_critical_failures(self) -> bool:
        """是否有关键失败项"""
        critical_checks = ['python_version', 'core_packages', 'third_party_packages']
        for check_name in critical_checks:
            if (check_name in self.check_results and 
                self.check_results[check_name].status == CheckStatus.FAILED):
                return True
        return False
    
    def generate_report(self) -> str:
        """生成详细的检查报告"""
        lines = []
        lines.append("=" * 60)
        lines.append("系统依赖检查报告")
        lines.append("=" * 60)
        lines.append("")
        
        # 总结
        if 'summary' in self.check_results:
            summary = self.check_results['summary']
            lines.append(f"检查结果: {summary.message}")
            lines.append("")
        
        # 详细结果
        for check_name, result in self.check_results.items():
            if check_name == 'summary':
                continue
                
            status_icon = {
                CheckStatus.PASSED: "✓",
                CheckStatus.FAILED: "✗",
                CheckStatus.WARNING: "⚠",
                CheckStatus.SKIPPED: "○"
            }.get(result.status, "?")
            
            lines.append(f"{status_icon} {result.name}: {result.message}")
            
            if result.fix_suggestions:
                lines.append("  修复建议:")
                for suggestion in result.fix_suggestions:
                    lines.append(f"    - {suggestion}")
                lines.append("")
        
        return "\n".join(lines)

# 便捷函数
def quick_check() -> bool:
    """
    快速检查，返回是否可以安全启动应用
    
    Returns:
        True如果可以安全启动，False如果有关键问题
    """
    checker = DependencyChecker()
    results = checker.check_all()
    return not checker.has_critical_failures()

def detailed_check() -> Dict[str, CheckResult]:
    """
    详细检查，返回完整的检查结果
    
    Returns:
        检查结果字典
    """
    checker = DependencyChecker()
    return checker.check_all()

__all__ = ['DependencyChecker', 'CheckStatus', 'CheckResult', 'quick_check', 'detailed_check']