#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具 - 安全启动脚本
解决闪退问题和使用问题的完整解决方案
"""

import sys
import os
import subprocess
import time
from pathlib import Path

def print_header():
    """打印程序头部信息"""
    print("=" * 60)
    print("Android系统修复工具 - 安全启动")
    print("版本: 1.0.0")
    print("=" * 60)
    print()

def check_python_version():
    """检查Python版本"""
    print("🔍 检查Python版本...")
    
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    if version >= (3, 8):
        print(f"✅ Python版本检查通过: {version_str}")
        return True
    else:
        print(f"❌ Python版本过低: {version_str}")
        print("   需要Python 3.8或更高版本")
        print("   请从 https://www.python.org/downloads/ 下载最新版本")
        return False

def check_required_packages():
    """检查必需的包"""
    print("🔍 检查必需的Python包...")
    
    required_packages = [
        'tkinter',
        'requests', 
        'psutil',
        'PIL'  # Pillow
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'PIL':
                import PIL
            else:
                __import__(package)
            print(f"✅ {package} - 已安装")
        except ImportError:
            print(f"❌ {package} - 缺失")
            missing_packages.append(package)
    
    if missing_packages:
        print("\n💡 解决方案:")
        print("   1. 运行以下命令安装缺失的包:")
        if 'PIL' in missing_packages:
            missing_packages.remove('PIL')
            missing_packages.append('Pillow')
        print(f"   pip install {' '.join(missing_packages)}")
        print("   2. 或者运行: pip install -r requirements.txt")
        return False
    
    return True

def check_adb():
    """检查ADB工具"""
    print("🔍 检查ADB工具...")
    
    # 检查PATH中的adb
    try:
        result = subprocess.run(['adb', 'version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            print("✅ ADB工具检查通过")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("❌ 未找到ADB工具")
    print("\n💡 解决方案:")
    print("   1. 下载Android SDK Platform Tools:")
    print("      https://developer.android.com/studio/releases/platform-tools")
    print("   2. 解压到任意目录并添加到PATH环境变量")
    print("   3. 或者安装Android Studio (包含ADB工具)")
    print("   4. 重启命令行窗口后再次运行")
    
    return False

def create_required_directories():
    """创建必需的目录"""
    print("🔍 检查必需目录...")
    
    required_dirs = [
        'logs',
        'data', 
        'backups',
        'data/quarantine',
        'data/virus_signatures',
        'data/system_resources'
    ]
    
    for dir_path in required_dirs:
        path = Path(dir_path)
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"✅ 创建目录: {dir_path}")
            except Exception as e:
                print(f"❌ 无法创建目录 {dir_path}: {e}")
                return False
        else:
            print(f"✅ 目录已存在: {dir_path}")
    
    return True

def check_config_file():
    """检查配置文件"""
    print("🔍 检查配置文件...")
    
    config_file = "config.ini"
    
    if not os.path.exists(config_file):
        print("⚠️ 配置文件不存在，创建默认配置...")
        
        default_config = """[app]
name = Android系统修复工具
version = 1.0.0
debug = false

[logging]
level = INFO
file = logs/app.log
max_size = 10MB
backup_count = 5

[adb]
timeout = 30
port = 5037
auto_detect = true

[gui]
theme = default
language = zh-CN
window_size = 1024x768

[paths]
data_dir = data
backup_dir = backups
log_dir = logs
"""
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(default_config)
            print("✅ 已创建默认配置文件")
            return True
        except Exception as e:
            print(f"❌ 无法创建配置文件: {e}")
            return False
    else:
        print("✅ 配置文件存在")
        return True

def check_permissions():
    """检查文件权限"""
    print("🔍 检查文件权限...")
    
    try:
        # 测试当前目录写权限
        test_file = Path('.test_write')
        test_file.write_text('test', encoding='utf-8')
        test_file.unlink()
        print("✅ 文件权限检查通过")
        return True
    except Exception as e:
        print(f"❌ 文件权限不足: {e}")
        print("\n💡 解决方案:")
        print("   1. 以管理员身份运行程序")
        print("   2. 检查文件夹权限设置")
        print("   3. 确保当前用户有读写权限")
        return False

def show_device_connection_guide():
    """显示设备连接指南"""
    print("\n" + "=" * 60)
    print("📱 Android设备连接指南")
    print("=" * 60)
    print()
    print("为了使用本工具，请按以下步骤连接您的Android设备:")
    print()
    print("步骤1: 启用开发者选项")
    print("   • 进入 设置 → 关于手机")
    print("   • 连续点击 \"版本号\" 7次")
    print("   • 提示 \"您现在是开发者\" 即可")
    print()
    print("步骤2: 启用USB调试")
    print("   • 进入 设置 → 开发者选项")
    print("   • 打开 \"USB调试\" 开关")
    print("   • 打开 \"USB安装\" 开关 (可选)")
    print()
    print("步骤3: 连接设备")
    print("   • 使用USB数据线连接手机和电脑")
    print("   • 手机屏幕会弹出授权对话框")
    print("   • 点击 \"允许\" 并勾选 \"始终允许来自此计算机\"")
    print()
    print("步骤4: 验证连接")
    print("   • 启动程序后，程序会自动检测设备")
    print("   • 如果连接成功，会显示设备信息")
    print()

def show_feature_guide():
    """显示功能使用指南"""
    print("=" * 60)
    print("🔧 主要功能说明")
    print("=" * 60)
    print()
    print("1. 设备管理")
    print("   • 自动检测和连接Android设备")
    print("   • 显示设备详细信息")
    print("   • 监控设备连接状态")
    print()
    print("2. 系统诊断")
    print("   • 检查系统健康状态")
    print("   • 分析存储空间使用情况")
    print("   • 检测系统文件完整性")
    print("   • 分析权限配置")
    print()
    print("3. 安全扫描")
    print("   • 病毒和恶意软件检测")
    print("   • 可疑应用识别")
    print("   • 权限异常分析")
    print()
    print("4. 文件清理")
    print("   • 清理缓存文件")
    print("   • 删除临时文件")
    print("   • 清理日志文件")
    print("   • 处理重复文件")
    print()
    print("5. 系统修复")
    print("   • 修复丢失的系统资源")
    print("   • 恢复损坏的系统文件")
    print("   • 一键修复常见问题")
    print()

def launch_application():
    """启动主应用程序"""
    print("🚀 启动应用程序...")
    
    try:
        # 首先尝试运行main.py
        if os.path.exists('main.py'):
            print("启动主程序: main.py")
            subprocess.run([sys.executable, 'main.py'], check=True)
        else:
            print("❌ 找不到main.py文件")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ 程序启动失败: {e}")
        print("\n可能的原因:")
        print("1. 依赖包未完全安装")
        print("2. 配置文件存在问题")
        print("3. 系统权限不足")
        print("4. 其他系统错误")
        return False
    except KeyboardInterrupt:
        print("\n用户中断程序运行")
        return True
    except Exception as e:
        print(f"❌ 启动异常: {e}")
        return False
    
    return True

def main():
    """主函数"""
    print_header()
    
    # 执行所有检查
    checks = [
        ("Python版本", check_python_version),
        ("Python包", check_required_packages), 
        ("必需目录", create_required_directories),
        ("配置文件", check_config_file),
        ("文件权限", check_permissions)
    ]
    
    print("开始系统检查...\n")
    
    failed_checks = []
    
    for check_name, check_func in checks:
        try:
            if not check_func():
                failed_checks.append(check_name)
        except Exception as e:
            print(f"❌ {check_name}检查异常: {e}")
            failed_checks.append(check_name)
        print()
    
    # ADB检查（非关键）
    adb_available = check_adb()
    print()
    
    # 显示检查结果
    if failed_checks:
        print("⚠️ 发现以下问题需要解决:")
        for i, check in enumerate(failed_checks, 1):
            print(f"   {i}. {check}")
        print()
        print("请解决上述问题后重新运行此脚本。")
        print()
        
        # 显示帮助信息
        if not adb_available:
            print("💡 ADB工具缺失不影响程序启动，但会影响设备连接功能。")
            print("   您可以稍后安装ADB工具，或在程序中手动配置。")
            print()
        
        input("按Enter键退出...")
        return 1
    
    print("✅ 所有关键检查都已通过！")
    
    if not adb_available:
        print("⚠️ ADB工具未安装，设备连接功能将受限。")
        print("   程序仍可正常启动，您可以稍后安装ADB工具。")
    
    print()
    
    # 显示使用指南
    show_device_connection_guide()
    show_feature_guide()
    
    # 询问是否启动
    print("=" * 60)
    response = input("是否现在启动程序？(y/n): ").lower().strip()
    
    if response in ['y', 'yes', '是', '']:
        print()
        success = launch_application()
        if success:
            print("\n程序运行完成。")
        else:
            print("\n程序启动失败，请检查错误信息。")
            input("按Enter键退出...")
            return 1
    else:
        print("\n您可以稍后手动运行: python main.py")
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n用户中断程序")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n启动脚本异常: {e}")
        input("按Enter键退出...")
        sys.exit(1)