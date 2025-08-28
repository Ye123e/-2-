#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
依赖检查器
用于检查和验证应用程序依赖，提供详细的错误诊断和修复建议
"""

import sys
import os
import subprocess
import importlib
import pkg_resources
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import platform
import logging
from dataclasses import dataclass

@dataclass
class DependencyInfo:
    """依赖信息"""
    name: str
    required_version: str = ""
    installed_version: str = ""
    is_available: bool = False
    is_version_compatible: bool = False
    import_error: Optional[str] = None
    install_command: str = ""
    description: str = ""

@dataclass
class SystemRequirement:
    """系统要求"""
    python_min_version: tuple = (3, 8)
    python_max_version: tuple = (3, 12)
    platform_supported: List[str] = None
    memory_min_mb: int = 512
    disk_space_min_mb: int = 100

class DependencyChecker:
    """依赖检查器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.project_root = Path(__file__).parent.parent.parent
        
        # 系统要求
        self.system_requirements = SystemRequirement(
            platform_supported=['Windows', 'Linux', 'Darwin']
        )
        
        # 核心依赖列表
        self.core_dependencies = {
            'tkinter': DependencyInfo(
                name='tkinter',
                description='GUI框架（Python内置）',
                install_command='内置模块，无需安装'
            ),
            'requests': DependencyInfo(
                name='requests',
                required_version='>=2.28.0',
                description='HTTP请求库',
                install_command='pip install requests>=2.28.0'
            ),
            'psutil': DependencyInfo(
                name='psutil',
                required_version='>=5.9.0',
                description='系统进程监控',
                install_command='pip install psutil>=5.9.0'
            ),
            'adb_shell': DependencyInfo(
                name='adb_shell',
                required_version='>=0.4.0',
                description='ADB连接库',
                install_command='pip install adb-shell>=0.4.0'
            ),
            'PIL': DependencyInfo(
                name='PIL',
                required_version='>=9.0.0',
                description='图像处理库',
                install_command='pip install Pillow>=9.0.0'
            )
        }
        
        # 可选依赖列表
        self.optional_dependencies = {
            'yara': DependencyInfo(
                name='yara',
                required_version='>=4.2.0',
                description='YARA规则引擎（病毒检测）',
                install_command='pip install yara-python>=4.2.0'
            ),
            'watchdog': DependencyInfo(
                name='watchdog',
                required_version='>=2.1.0',
                description='文件系统监控',
                install_command='pip install watchdog>=2.1.0'
            ),
            'coloredlogs': DependencyInfo(
                name='coloredlogs',
                required_version='>=15.0',
                description='彩色日志输出',
                install_command='pip install coloredlogs>=15.0'
            )
        }
    
    def check_all_dependencies(self) -> Dict[str, Any]:
        """检查所有依赖项"""
        results = {
            'system_check': self._check_system_requirements(),
            'core_dependencies': self._check_dependencies(self.core_dependencies),
            'optional_dependencies': self._check_dependencies(self.optional_dependencies),
            'project_structure': self._check_project_structure(),
            'permissions': self._check_permissions(),
            'summary': {}
        }
        
        # 生成摘要
        results['summary'] = self._generate_summary(results)
        return results
    
    def _check_system_requirements(self) -> Dict[str, Any]:
        """检查系统要求"""
        results = {
            'python_version': {
                'current': sys.version_info[:3],
                'required_min': self.system_requirements.python_min_version,
                'required_max': self.system_requirements.python_max_version,
                'compatible': False,
                'details': ''
            },
            'platform': {
                'current': platform.system(),
                'supported': self.system_requirements.platform_supported,
                'compatible': False,
                'details': ''
            },
            'memory': {
                'available_mb': self._get_available_memory(),
                'required_mb': self.system_requirements.memory_min_mb,
                'sufficient': False,
                'details': ''
            },
            'disk_space': {
                'available_mb': self._get_available_disk_space(),
                'required_mb': self.system_requirements.disk_space_min_mb,
                'sufficient': False,
                'details': ''
            }
        }
        
        # 检查Python版本
        current_version = sys.version_info[:2]
        min_version = self.system_requirements.python_min_version
        max_version = self.system_requirements.python_max_version
        
        if min_version <= current_version <= max_version:
            results['python_version']['compatible'] = True
            results['python_version']['details'] = f"Python {'.'.join(map(str, current_version))} 符合要求"
        else:
            results['python_version']['details'] = f"Python版本不兼容，当前：{'.'.join(map(str, current_version))}，要求：{'.'.join(map(str, min_version))}-{'.'.join(map(str, max_version))}"
        
        # 检查平台
        current_platform = platform.system()
        if current_platform in self.system_requirements.platform_supported:
            results['platform']['compatible'] = True
            results['platform']['details'] = f"平台 {current_platform} 受支持"
        else:
            results['platform']['details'] = f"平台 {current_platform} 可能不受支持"
        
        # 检查内存
        available_memory = results['memory']['available_mb']
        if available_memory >= self.system_requirements.memory_min_mb:
            results['memory']['sufficient'] = True
            results['memory']['details'] = f"可用内存 {available_memory}MB 充足"
        else:
            results['memory']['details'] = f"可用内存不足：{available_memory}MB < {self.system_requirements.memory_min_mb}MB"
        
        # 检查磁盘空间
        available_disk = results['disk_space']['available_mb']
        if available_disk >= self.system_requirements.disk_space_min_mb:
            results['disk_space']['sufficient'] = True
            results['disk_space']['details'] = f"可用磁盘空间 {available_disk}MB 充足"
        else:
            results['disk_space']['details'] = f"磁盘空间不足：{available_disk}MB < {self.system_requirements.disk_space_min_mb}MB"
        
        return results
    
    def _check_dependencies(self, dependencies: Dict[str, DependencyInfo]) -> Dict[str, DependencyInfo]:
        """检查依赖项"""
        results = {}
        
        for dep_name, dep_info in dependencies.items():
            result = DependencyInfo(**dep_info.__dict__)
            
            try:
                # 尝试导入模块
                if dep_name == 'PIL':
                    # Pillow特殊处理
                    import PIL
                    module = PIL
                    result.installed_version = PIL.__version__
                else:
                    module = importlib.import_module(dep_name)
                    
                    # 获取版本信息
                    if hasattr(module, '__version__'):
                        result.installed_version = module.__version__
                    else:
                        try:
                            result.installed_version = pkg_resources.get_distribution(dep_name).version
                        except:
                            result.installed_version = "未知版本"
                
                result.is_available = True
                
                # 检查版本兼容性
                if result.required_version and result.installed_version != "未知版本":
                    result.is_version_compatible = self._check_version_compatibility(
                        result.installed_version, result.required_version
                    )
                else:
                    result.is_version_compatible = True
                
            except ImportError as e:
                result.is_available = False
                result.import_error = str(e)
            except Exception as e:
                result.is_available = False
                result.import_error = f"检查异常: {str(e)}"
            
            results[dep_name] = result
        
        return results
    
    def _check_version_compatibility(self, installed_version: str, required_version: str) -> bool:
        """检查版本兼容性"""
        try:
            if required_version.startswith('>='):
                required = required_version[2:].strip()
                return self._compare_versions(installed_version, required) >= 0
            elif required_version.startswith('<='):
                required = required_version[2:].strip()
                return self._compare_versions(installed_version, required) <= 0
            elif required_version.startswith('>'):
                required = required_version[1:].strip()
                return self._compare_versions(installed_version, required) > 0
            elif required_version.startswith('<'):
                required = required_version[1:].strip()
                return self._compare_versions(installed_version, required) < 0
            elif required_version.startswith('=='):
                required = required_version[2:].strip()
                return self._compare_versions(installed_version, required) == 0
            else:
                return self._compare_versions(installed_version, required_version) >= 0
        except:
            return True  # 如果版本比较失败，假设兼容
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """比较版本号"""
        def normalize_version(version):
            return [int(x) for x in version.split('.')]
        
        v1 = normalize_version(version1)
        v2 = normalize_version(version2)
        
        # 补齐长度
        max_len = max(len(v1), len(v2))
        v1.extend([0] * (max_len - len(v1)))
        v2.extend([0] * (max_len - len(v2)))
        
        for i in range(max_len):
            if v1[i] < v2[i]:
                return -1
            elif v1[i] > v2[i]:
                return 1
        
        return 0
    
    def _check_project_structure(self) -> Dict[str, Any]:
        """检查项目结构"""
        required_dirs = [
            'src', 'src/core', 'src/gui', 'src/config', 
            'src/utils', 'src/models', 'logs', 'data'
        ]
        
        required_files = [
            'main.py', 'start.py', 'config.ini', 'requirements.txt',
            'src/__init__.py', 'src/gui/__init__.py', 'src/core/__init__.py',
            'src/config/__init__.py', 'src/utils/__init__.py', 'src/models/__init__.py'
        ]
        
        results = {
            'directories': {},
            'files': {},
            'missing_directories': [],
            'missing_files': [],
            'structure_valid': True
        }
        
        # 检查目录
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            exists = full_path.exists() and full_path.is_dir()
            results['directories'][dir_path] = exists
            
            if not exists:
                results['missing_directories'].append(dir_path)
                results['structure_valid'] = False
        
        # 检查文件
        for file_path in required_files:
            full_path = self.project_root / file_path
            exists = full_path.exists() and full_path.is_file()
            results['files'][file_path] = exists
            
            if not exists:
                results['missing_files'].append(file_path)
                results['structure_valid'] = False
        
        return results
    
    def _check_permissions(self) -> Dict[str, Any]:
        """检查权限"""
        results = {
            'project_directory': {
                'readable': False,
                'writable': False,
                'executable': False
            },
            'logs_directory': {
                'readable': False,
                'writable': False,
                'executable': False
            },
            'data_directory': {
                'readable': False,
                'writable': False,
                'executable': False
            }
        }
        
        # 检查项目目录权限
        try:
            results['project_directory']['readable'] = os.access(self.project_root, os.R_OK)
            results['project_directory']['writable'] = os.access(self.project_root, os.W_OK)
            results['project_directory']['executable'] = os.access(self.project_root, os.X_OK)
        except:
            pass
        
        # 检查logs目录权限
        logs_dir = self.project_root / 'logs'
        if logs_dir.exists():
            try:
                results['logs_directory']['readable'] = os.access(logs_dir, os.R_OK)
                results['logs_directory']['writable'] = os.access(logs_dir, os.W_OK)
                results['logs_directory']['executable'] = os.access(logs_dir, os.X_OK)
            except:
                pass
        
        # 检查data目录权限
        data_dir = self.project_root / 'data'
        if data_dir.exists():
            try:
                results['data_directory']['readable'] = os.access(data_dir, os.R_OK)
                results['data_directory']['writable'] = os.access(data_dir, os.W_OK)
                results['data_directory']['executable'] = os.access(data_dir, os.X_OK)
            except:
                pass
        
        return results
    
    def _get_available_memory(self) -> int:
        """获取可用内存（MB）"""
        try:
            import psutil
            return int(psutil.virtual_memory().available / 1024 / 1024)
        except:
            return 0
    
    def _get_available_disk_space(self) -> int:
        """获取可用磁盘空间（MB）"""
        try:
            import psutil
            disk_usage = psutil.disk_usage(str(self.project_root))
            return int(disk_usage.free / 1024 / 1024)
        except:
            return 0
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成检查摘要"""
        summary = {
            'overall_status': 'PASS',
            'issues_found': [],
            'warnings': [],
            'recommendations': [],
            'critical_issues': 0,
            'warning_issues': 0
        }
        
        # 检查系统要求
        system_check = results['system_check']
        if not system_check['python_version']['compatible']:
            summary['issues_found'].append({
                'type': 'CRITICAL',
                'category': 'SYSTEM',
                'message': system_check['python_version']['details'],
                'fix': '请升级或降级Python到支持的版本'
            })
            summary['critical_issues'] += 1
            summary['overall_status'] = 'FAIL'
        
        if not system_check['platform']['compatible']:
            summary['warnings'].append({
                'type': 'WARNING',
                'category': 'SYSTEM',
                'message': system_check['platform']['details'],
                'fix': '当前平台可能存在兼容性问题'
            })
            summary['warning_issues'] += 1
        
        # 检查核心依赖
        for dep_name, dep_info in results['core_dependencies'].items():
            if not dep_info.is_available:
                summary['issues_found'].append({
                    'type': 'CRITICAL',
                    'category': 'DEPENDENCY',
                    'message': f'核心依赖 {dep_name} 缺失: {dep_info.import_error}',
                    'fix': dep_info.install_command
                })
                summary['critical_issues'] += 1
                summary['overall_status'] = 'FAIL'
            elif not dep_info.is_version_compatible:
                summary['warnings'].append({
                    'type': 'WARNING',
                    'category': 'DEPENDENCY',
                    'message': f'依赖 {dep_name} 版本不兼容: 当前{dep_info.installed_version}，要求{dep_info.required_version}',
                    'fix': dep_info.install_command
                })
                summary['warning_issues'] += 1
        
        # 检查项目结构
        structure_check = results['project_structure']
        if not structure_check['structure_valid']:
            if structure_check['missing_directories']:
                summary['issues_found'].append({
                    'type': 'CRITICAL',
                    'category': 'STRUCTURE',
                    'message': f'缺少目录: {", ".join(structure_check["missing_directories"])}',
                    'fix': '运行 python start.py 自动创建目录'
                })
                summary['critical_issues'] += 1
                summary['overall_status'] = 'FAIL'
            
            if structure_check['missing_files']:
                summary['issues_found'].append({
                    'type': 'CRITICAL',
                    'category': 'STRUCTURE',
                    'message': f'缺少文件: {", ".join(structure_check["missing_files"])}',
                    'fix': '请检查项目文件是否完整'
                })
                summary['critical_issues'] += 1
                summary['overall_status'] = 'FAIL'
        
        # 生成建议
        if summary['critical_issues'] == 0 and summary['warning_issues'] == 0:
            summary['recommendations'].append('✅ 所有检查通过，系统准备就绪')
        else:
            if summary['critical_issues'] > 0:
                summary['recommendations'].append('🔴 发现关键问题，请先解决这些问题再启动应用')
            if summary['warning_issues'] > 0:
                summary['recommendations'].append('🟡 发现警告，建议修复以获得最佳体验')
        
        return summary
    
    def generate_fix_script(self, results: Dict[str, Any]) -> str:
        """生成修复脚本"""
        script_lines = [
            "#!/usr/bin/env python3",
            "# -*- coding: utf-8 -*-",
            "# Android系统修复工具 - 自动修复脚本",
            "",
            "import subprocess",
            "import sys",
            "import os",
            "",
            "def run_command(command):",
            "    \"\"\"执行命令\"\"\"",
            "    try:",
            "        result = subprocess.run(command, shell=True, capture_output=True, text=True)",
            "        return result.returncode == 0, result.stdout, result.stderr",
            "    except Exception as e:",
            "        return False, '', str(e)",
            "",
            "def main():",
            "    print('开始自动修复...')",
            "    fixes_applied = 0",
            "",
        ]
        
        # 添加依赖安装命令
        for dep_name, dep_info in results['core_dependencies'].items():
            if not dep_info.is_available and dep_info.install_command.startswith('pip'):
                script_lines.extend([
                    f"    # 安装 {dep_name}",
                    f"    print('正在安装 {dep_name}...')",
                    f"    success, stdout, stderr = run_command('{dep_info.install_command}')",
                    f"    if success:",
                    f"        print('✅ {dep_name} 安装成功')",
                    f"        fixes_applied += 1",
                    f"    else:",
                    f"        print('❌ {dep_name} 安装失败:', stderr)",
                    "",
                ])
        
        # 添加目录创建命令
        structure_check = results['project_structure']
        if structure_check['missing_directories']:
            script_lines.extend([
                "    # 创建缺失目录",
                "    directories = " + str(structure_check['missing_directories']),
                "    for directory in directories:",
                "        try:",
                "            os.makedirs(directory, exist_ok=True)",
                "            print(f'✅ 创建目录: {directory}')",
                "            fixes_applied += 1",
                "        except Exception as e:",
                "            print(f'❌ 创建目录失败 {directory}: {e}')",
                "",
            ])
        
        script_lines.extend([
            "    print(f'修复完成，应用了 {fixes_applied} 个修复')",
            "    if fixes_applied > 0:",
            "        print('请重新运行依赖检查验证修复结果')",
            "",
            "if __name__ == '__main__':",
            "    main()"
        ])
        
        return '\n'.join(script_lines)
    
    def print_detailed_report(self, results: Dict[str, Any]):
        """打印详细报告"""
        print("=" * 80)
        print("Android系统修复工具 - 依赖检查报告")
        print("=" * 80)
        
        # 打印摘要
        summary = results['summary']
        print(f"\n📊 检查摘要:")
        print(f"整体状态: {'✅ 通过' if summary['overall_status'] == 'PASS' else '❌ 失败'}")
        print(f"关键问题: {summary['critical_issues']} 个")
        print(f"警告问题: {summary['warning_issues']} 个")
        
        # 打印系统检查
        print(f"\n🖥️ 系统检查:")
        system_check = results['system_check']
        print(f"Python版本: {'✅' if system_check['python_version']['compatible'] else '❌'} {system_check['python_version']['details']}")
        print(f"操作系统: {'✅' if system_check['platform']['compatible'] else '⚠️'} {system_check['platform']['details']}")
        print(f"内存检查: {'✅' if system_check['memory']['sufficient'] else '❌'} {system_check['memory']['details']}")
        print(f"磁盘空间: {'✅' if system_check['disk_space']['sufficient'] else '❌'} {system_check['disk_space']['details']}")
        
        # 打印核心依赖
        print(f"\n📦 核心依赖:")
        for dep_name, dep_info in results['core_dependencies'].items():
            status = "✅" if dep_info.is_available and dep_info.is_version_compatible else "❌"
            version_text = f"({dep_info.installed_version})" if dep_info.installed_version else ""
            print(f"{status} {dep_name} {version_text} - {dep_info.description}")
            if not dep_info.is_available:
                print(f"    错误: {dep_info.import_error}")
                print(f"    修复: {dep_info.install_command}")
        
        # 打印可选依赖
        print(f"\n🔧 可选依赖:")
        for dep_name, dep_info in results['optional_dependencies'].items():
            status = "✅" if dep_info.is_available else "⚠️"
            version_text = f"({dep_info.installed_version})" if dep_info.installed_version else ""
            print(f"{status} {dep_name} {version_text} - {dep_info.description}")
        
        # 打印项目结构
        print(f"\n📁 项目结构:")
        structure_check = results['project_structure']
        if structure_check['structure_valid']:
            print("✅ 项目结构完整")
        else:
            print("❌ 项目结构不完整")
            if structure_check['missing_directories']:
                print(f"    缺少目录: {', '.join(structure_check['missing_directories'])}")
            if structure_check['missing_files']:
                print(f"    缺少文件: {', '.join(structure_check['missing_files'])}")
        
        # 打印问题和建议
        if summary['issues_found']:
            print(f"\n🔴 发现的问题:")
            for issue in summary['issues_found']:
                print(f"  [{issue['type']}] {issue['message']}")
                print(f"      修复方案: {issue['fix']}")
        
        if summary['warnings']:
            print(f"\n🟡 警告:")
            for warning in summary['warnings']:
                print(f"  [{warning['type']}] {warning['message']}")
                print(f"      建议: {warning['fix']}")
        
        print(f"\n💡 建议:")
        for recommendation in summary['recommendations']:
            print(f"  {recommendation}")
        
        print("=" * 80)

def main():
    """主函数"""
    checker = DependencyChecker()
    results = checker.check_all_dependencies()
    
    # 打印详细报告
    checker.print_detailed_report(results)
    
    # 如果有问题，生成修复脚本
    if results['summary']['critical_issues'] > 0:
        print("\n🔧 生成自动修复脚本...")
        fix_script = checker.generate_fix_script(results)
        
        script_path = Path(__file__).parent.parent.parent / 'auto_fix.py'
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(fix_script)
        
        print(f"✅ 修复脚本已生成: {script_path}")
        print("运行命令: python auto_fix.py")
    
    return results['summary']['overall_status'] == 'PASS'

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)