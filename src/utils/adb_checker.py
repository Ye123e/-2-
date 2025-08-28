#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADB配置检查和自动修复工具
用于检测、诊断和修复ADB相关的配置问题
"""

import os
import sys
import subprocess
import shutil
import platform
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging

@dataclass
class AdbInfo:
    """ADB信息"""
    path: Optional[str] = None
    version: str = ""
    is_available: bool = False
    is_running: bool = False
    port: int = 5037
    devices_count: int = 0
    error_message: str = ""

@dataclass
class AdbDiagnostic:
    """ADB诊断结果"""
    overall_status: str = "UNKNOWN"  # OK, WARNING, ERROR
    issues_found: List[Dict[str, Any]] = None
    recommendations: List[str] = None
    auto_fixes_available: bool = False
    
    def __post_init__(self):
        if self.issues_found is None:
            self.issues_found = []
        if self.recommendations is None:
            self.recommendations = []

class AdbConfigChecker:
    """ADB配置检查器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system()
        self.adb_executable = "adb.exe" if self.platform == "Windows" else "adb"
        
        # 常见ADB安装路径
        self.common_adb_paths = self._get_common_adb_paths()
        
    def _get_common_adb_paths(self) -> List[str]:
        """获取常见ADB安装路径"""
        paths = []
        
        if self.platform == "Windows":
            # Windows常见路径
            possible_dirs = [
                os.path.expanduser("~/AppData/Local/Android/Sdk/platform-tools"),
                "C:/Program Files/Android/Android Studio/bin",
                "C:/Android/Sdk/platform-tools",
                "C:/adb",
                "C:/platform-tools"
            ]
            
            # 检查环境变量
            android_home = os.environ.get("ANDROID_HOME")
            if android_home:
                possible_dirs.append(os.path.join(android_home, "platform-tools"))
                
            android_sdk_root = os.environ.get("ANDROID_SDK_ROOT")
            if android_sdk_root:
                possible_dirs.append(os.path.join(android_sdk_root, "platform-tools"))
            
            for dir_path in possible_dirs:
                adb_path = os.path.join(dir_path, self.adb_executable)
                if os.path.exists(adb_path):
                    paths.append(adb_path)
        
        elif self.platform == "Linux":
            # Linux常见路径
            possible_dirs = [
                os.path.expanduser("~/Android/Sdk/platform-tools"),
                "/opt/android-sdk/platform-tools",
                "/usr/local/android-sdk/platform-tools",
                "/usr/bin",
                "/usr/local/bin"
            ]
            
            android_home = os.environ.get("ANDROID_HOME")
            if android_home:
                possible_dirs.append(os.path.join(android_home, "platform-tools"))
            
            for dir_path in possible_dirs:
                adb_path = os.path.join(dir_path, self.adb_executable)
                if os.path.exists(adb_path):
                    paths.append(adb_path)
        
        elif self.platform == "Darwin":
            # macOS常见路径
            possible_dirs = [
                os.path.expanduser("~/Library/Android/sdk/platform-tools"),
                "/Users/Shared/Android/sdk/platform-tools",
                "/opt/android-sdk/platform-tools"
            ]
            
            android_home = os.environ.get("ANDROID_HOME")
            if android_home:
                possible_dirs.append(os.path.join(android_home, "platform-tools"))
            
            for dir_path in possible_dirs:
                adb_path = os.path.join(dir_path, self.adb_executable)
                if os.path.exists(adb_path):
                    paths.append(adb_path)
        
        return paths
    
    def detect_adb(self) -> AdbInfo:
        """检测ADB安装"""
        adb_info = AdbInfo()
        
        try:
            # 1. 检查PATH中的ADB
            adb_path = shutil.which(self.adb_executable)
            if adb_path:
                adb_info.path = adb_path
                adb_info.is_available = True
                self.logger.info(f"在PATH中找到ADB: {adb_path}")
            else:
                # 2. 检查常见安装位置
                for path in self.common_adb_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        adb_info.path = path
                        adb_info.is_available = True
                        self.logger.info(f"在常见位置找到ADB: {path}")
                        break
            
            if adb_info.is_available:
                # 获取ADB版本
                try:
                    result = subprocess.run(
                        [adb_info.path, "version"],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        adb_info.version = result.stdout.strip()
                    else:
                        adb_info.error_message = result.stderr.strip()
                except subprocess.TimeoutExpired:
                    adb_info.error_message = "ADB版本检查超时"
                except Exception as e:
                    adb_info.error_message = f"ADB版本检查失败: {str(e)}"
            else:
                adb_info.error_message = "未找到ADB可执行文件"
                
        except Exception as e:
            adb_info.error_message = f"ADB检测异常: {str(e)}"
            self.logger.error(f"ADB检测异常: {e}")
        
        return adb_info
    
    def check_adb_server(self, adb_path: str) -> Tuple[bool, int, str]:
        """检查ADB服务器状态"""
        try:
            # 检查ADB服务器状态
            result = subprocess.run(
                [adb_path, "get-state"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                return True, 5037, "ADB服务器运行正常"
            else:
                # 尝试启动ADB服务器
                start_result = subprocess.run(
                    [adb_path, "start-server"],
                    capture_output=True, text=True, timeout=10
                )
                
                if start_result.returncode == 0:
                    return True, 5037, "ADB服务器已启动"
                else:
                    return False, 0, f"ADB服务器启动失败: {start_result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, 0, "ADB服务器检查超时"
        except Exception as e:
            return False, 0, f"ADB服务器检查异常: {str(e)}"
    
    def check_devices(self, adb_path: str) -> Tuple[int, List[Dict[str, str]], str]:
        """检查连接的设备"""
        try:
            result = subprocess.run(
                [adb_path, "devices"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                devices = []
                lines = result.stdout.strip().split('\n')[1:]  # 跳过标题行
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('*'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            devices.append({
                                'device_id': parts[0],
                                'status': parts[1]
                            })
                
                return len(devices), devices, "设备检查成功"
            else:
                return 0, [], f"设备检查失败: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return 0, [], "设备检查超时"
        except Exception as e:
            return 0, [], f"设备检查异常: {str(e)}"
    
    def check_usb_debugging_requirements(self) -> Dict[str, Any]:
        """检查USB调试相关要求"""
        requirements = {
            'driver_status': 'unknown',
            'usb_ports': [],
            'system_info': {},
            'recommendations': []
        }
        
        try:
            # 获取系统信息
            requirements['system_info'] = {
                'platform': self.platform,
                'version': platform.version(),
                'architecture': platform.machine()
            }
            
            if self.platform == "Windows":
                requirements.update(self._check_windows_usb_requirements())
            elif self.platform == "Linux":
                requirements.update(self._check_linux_usb_requirements())
            elif self.platform == "Darwin":
                requirements.update(self._check_macos_usb_requirements())
        
        except Exception as e:
            requirements['error'] = f"USB调试要求检查失败: {str(e)}"
        
        return requirements
    
    def _check_windows_usb_requirements(self) -> Dict[str, Any]:
        """检查Windows USB要求"""
        result = {
            'driver_status': 'unknown',
            'recommendations': []
        }
        
        # 检查USB驱动（需要管理员权限，这里只做基础检查）
        result['recommendations'].extend([
            "确保已安装Android USB驱动程序",
            "在设备管理器中检查设备状态",
            "尝试不同的USB端口和数据线"
        ])
        
        return result
    
    def _check_linux_usb_requirements(self) -> Dict[str, Any]:
        """检查Linux USB要求"""
        result = {
            'driver_status': 'built_in',
            'recommendations': []
        }
        
        # 检查udev规则
        udev_rules = [
            "/etc/udev/rules.d/51-android.rules",
            "/lib/udev/rules.d/51-android.rules"
        ]
        
        udev_found = any(os.path.exists(rule) for rule in udev_rules)
        if not udev_found:
            result['recommendations'].append("创建Android udev规则文件")
        
        # 检查用户组
        try:
            import grp
            plugdev_group = grp.getgrnam('plugdev')
            current_user = os.getenv('USER')
            if current_user not in plugdev_group.gr_mem:
                result['recommendations'].append(f"将用户 {current_user} 添加到 plugdev 组")
        except:
            pass
        
        return result
    
    def _check_macos_usb_requirements(self) -> Dict[str, Any]:
        """检查macOS USB要求"""
        result = {
            'driver_status': 'built_in',
            'recommendations': [
                "确保信任计算机的对话框已确认",
                "检查系统偏好设置中的安全设置"
            ]
        }
        
        return result
    
    def run_comprehensive_check(self) -> AdbDiagnostic:
        """运行全面的ADB检查"""
        diagnostic = AdbDiagnostic()
        
        print("🔍 正在运行ADB配置全面检查...")
        
        # 1. 检测ADB安装
        print("  📦 检查ADB安装...")
        adb_info = self.detect_adb()
        
        if not adb_info.is_available:
            diagnostic.overall_status = "ERROR"
            diagnostic.issues_found.append({
                'type': 'CRITICAL',
                'category': 'ADB_MISSING',
                'message': 'ADB未安装或未找到',
                'details': adb_info.error_message,
                'fix': 'install_adb'
            })
            diagnostic.recommendations.extend([
                "下载并安装Android SDK Platform Tools",
                "将ADB添加到系统PATH环境变量",
                "确保ADB文件具有执行权限"
            ])
            diagnostic.auto_fixes_available = True
            return diagnostic
        
        print(f"  ✅ ADB已找到: {adb_info.path}")
        print(f"  📋 版本信息: {adb_info.version.split()[0] if adb_info.version else '未知'}")
        
        # 2. 检查ADB服务器
        print("  🔄 检查ADB服务器状态...")
        server_running, port, server_msg = self.check_adb_server(adb_info.path)
        
        if not server_running:
            diagnostic.issues_found.append({
                'type': 'WARNING',
                'category': 'ADB_SERVER',
                'message': 'ADB服务器未运行',
                'details': server_msg,
                'fix': 'restart_adb_server'
            })
            diagnostic.auto_fixes_available = True
        else:
            print(f"  ✅ ADB服务器运行正常 (端口: {port})")
        
        # 3. 检查设备连接
        print("  📱 检查连接的设备...")
        device_count, devices, device_msg = self.check_devices(adb_info.path)
        
        print(f"  📊 发现 {device_count} 个设备")
        
        if device_count == 0:
            diagnostic.issues_found.append({
                'type': 'INFO',
                'category': 'NO_DEVICES',
                'message': '未检测到连接的设备',
                'details': '没有设备连接或设备未启用USB调试',
                'fix': 'guide_device_connection'
            })
            diagnostic.recommendations.extend([
                "连接Android设备到USB端口",
                "在设备上启用开发者选项和USB调试",
                "确认设备上的USB调试授权对话框"
            ])
        else:
            unauthorized_devices = [d for d in devices if d['status'] == 'unauthorized']
            offline_devices = [d for d in devices if d['status'] == 'offline']
            
            if unauthorized_devices:
                diagnostic.issues_found.append({
                    'type': 'WARNING',
                    'category': 'DEVICE_UNAUTHORIZED',
                    'message': f'{len(unauthorized_devices)} 个设备未授权',
                    'details': '设备需要用户确认USB调试授权',
                    'fix': 'guide_authorization'
                })
            
            if offline_devices:
                diagnostic.issues_found.append({
                    'type': 'WARNING',
                    'category': 'DEVICE_OFFLINE',
                    'message': f'{len(offline_devices)} 个设备离线',
                    'details': '设备连接不稳定或驱动问题',
                    'fix': 'troubleshoot_connection'
                })
            
            # 显示设备详情
            for device in devices:
                status_emoji = {
                    'device': '✅',
                    'unauthorized': '🔒',
                    'offline': '❌'
                }.get(device['status'], '❓')
                print(f"    {status_emoji} {device['device_id']} - {device['status']}")
        
        # 4. 检查USB调试要求
        print("  🔌 检查USB调试要求...")
        usb_requirements = self.check_usb_debugging_requirements()
        
        if 'error' in usb_requirements:
            diagnostic.issues_found.append({
                'type': 'WARNING',
                'category': 'USB_CHECK',
                'message': 'USB要求检查失败',
                'details': usb_requirements['error'],
                'fix': 'manual_usb_check'
            })
        
        if usb_requirements['recommendations']:
            diagnostic.recommendations.extend(usb_requirements['recommendations'])
        
        # 设置整体状态
        if not diagnostic.issues_found:
            diagnostic.overall_status = "OK"
            diagnostic.recommendations.append("✅ ADB配置检查通过，系统准备就绪")
        else:
            error_count = len([i for i in diagnostic.issues_found if i['type'] == 'CRITICAL'])
            warning_count = len([i for i in diagnostic.issues_found if i['type'] == 'WARNING'])
            
            if error_count > 0:
                diagnostic.overall_status = "ERROR"
            elif warning_count > 0:
                diagnostic.overall_status = "WARNING"
            else:
                diagnostic.overall_status = "OK"
        
        return diagnostic
    
    def auto_fix_issues(self, diagnostic: AdbDiagnostic) -> bool:
        """自动修复发现的问题"""
        if not diagnostic.auto_fixes_available:
            print("❌ 没有可自动修复的问题")
            return False
        
        print("🔧 正在尝试自动修复...")
        fixed_count = 0
        
        for issue in diagnostic.issues_found:
            fix_type = issue.get('fix', '')
            
            if fix_type == 'restart_adb_server':
                if self._fix_adb_server():
                    print(f"  ✅ 已修复: {issue['message']}")
                    fixed_count += 1
                else:
                    print(f"  ❌ 修复失败: {issue['message']}")
            
            elif fix_type == 'install_adb':
                print(f"  ℹ️  需要手动修复: {issue['message']}")
                print("     请访问: https://developer.android.com/studio/releases/platform-tools")
        
        print(f"\n🎯 自动修复完成: {fixed_count} 个问题已修复")
        return fixed_count > 0
    
    def _fix_adb_server(self) -> bool:
        """修复ADB服务器"""
        try:
            adb_info = self.detect_adb()
            if not adb_info.is_available:
                return False
            
            # 停止ADB服务器
            subprocess.run(
                [adb_info.path, "kill-server"],
                capture_output=True, timeout=10
            )
            
            time.sleep(2)
            
            # 启动ADB服务器
            result = subprocess.run(
                [adb_info.path, "start-server"],
                capture_output=True, text=True, timeout=10
            )
            
            return result.returncode == 0
        
        except Exception as e:
            self.logger.error(f"ADB服务器修复失败: {e}")
            return False
    
    def generate_config_suggestions(self, diagnostic: AdbDiagnostic) -> Dict[str, Any]:
        """生成配置建议"""
        suggestions = {
            'config_updates': {},
            'environment_variables': {},
            'manual_steps': []
        }
        
        # 检测到的ADB路径
        adb_info = self.detect_adb()
        if adb_info.is_available:
            suggestions['config_updates']['adb_path'] = adb_info.path
            suggestions['environment_variables']['ADB_PATH'] = adb_info.path
        
        # 根据问题生成建议
        for issue in diagnostic.issues_found:
            if issue['category'] == 'ADB_MISSING':
                suggestions['manual_steps'].extend([
                    "1. 下载Android SDK Platform Tools",
                    "2. 解压到合适的目录",
                    "3. 将目录添加到PATH环境变量",
                    "4. 重启终端或IDE"
                ])
            
            elif issue['category'] == 'DEVICE_UNAUTHORIZED':
                suggestions['manual_steps'].extend([
                    "1. 在Android设备上查找USB调试授权对话框",
                    "2. 勾选'始终允许从这台计算机'",
                    "3. 点击'确定'进行授权"
                ])
        
        return suggestions
    
    def print_diagnostic_report(self, diagnostic: AdbDiagnostic):
        """打印诊断报告"""
        print("\n" + "=" * 80)
        print("🔧 ADB配置诊断报告")
        print("=" * 80)
        
        # 整体状态
        status_emoji = {
            'OK': '✅',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'UNKNOWN': '❓'
        }.get(diagnostic.overall_status, '❓')
        
        print(f"\n📊 整体状态: {status_emoji} {diagnostic.overall_status}")
        
        # 发现的问题
        if diagnostic.issues_found:
            print(f"\n🔍 发现的问题 ({len(diagnostic.issues_found)}个):")
            for i, issue in enumerate(diagnostic.issues_found, 1):
                type_emoji = {
                    'CRITICAL': '🔴',
                    'WARNING': '🟡',
                    'INFO': 'ℹ️'
                }.get(issue['type'], '❓')
                
                print(f"  {i}. {type_emoji} [{issue['type']}] {issue['message']}")
                if issue.get('details'):
                    print(f"     详情: {issue['details']}")
        
        # 建议
        if diagnostic.recommendations:
            print(f"\n💡 建议 ({len(diagnostic.recommendations)}条):")
            for i, rec in enumerate(diagnostic.recommendations, 1):
                print(f"  {i}. {rec}")
        
        # 自动修复
        if diagnostic.auto_fixes_available:
            print(f"\n🔧 有 {len([i for i in diagnostic.issues_found if 'fix' in i])} 个问题可以尝试自动修复")
            print("   运行: python -m src.utils.adb_checker --fix")
        
        print("=" * 80)

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ADB配置检查和修复工具")
    parser.add_argument("--fix", action="store_true", help="尝试自动修复发现的问题")
    parser.add_argument("--config", action="store_true", help="生成配置建议")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    checker = AdbConfigChecker()
    
    # 运行诊断
    diagnostic = checker.run_comprehensive_check()
    
    # 打印报告
    checker.print_diagnostic_report(diagnostic)
    
    # 自动修复
    if args.fix and diagnostic.auto_fixes_available:
        print("\n🔧 开始自动修复...")
        fixed = checker.auto_fix_issues(diagnostic)
        
        if fixed:
            print("\n🔄 重新运行诊断...")
            diagnostic = checker.run_comprehensive_check()
            checker.print_diagnostic_report(diagnostic)
    
    # 生成配置建议
    if args.config:
        print("\n⚙️ 配置建议:")
        suggestions = checker.generate_config_suggestions(diagnostic)
        print(json.dumps(suggestions, indent=2, ensure_ascii=False))
    
    # 返回状态码
    return 0 if diagnostic.overall_status in ['OK', 'WARNING'] else 1

if __name__ == "__main__":
    sys.exit(main())