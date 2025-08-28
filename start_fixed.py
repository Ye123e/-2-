#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具启动脚本
用于测试和启动应用程序，包含完整的错误诊断和处理机制
"""

import sys
import os
import logging
import traceback
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Any
import time
import platform

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 配置基础日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def check_dependencies() -> Dict[str, Any]:
    """检查依赖项，返回详细检查结果"""
    print("🔍 正在检查依赖项...")
    
    # 核心依赖列表
    core_modules = {
        'tkinter': {'description': 'GUI框架（内置）', 'critical': True},
        'requests': {'description': 'HTTP请求库', 'critical': True},
        'psutil': {'description': '系统监控库', 'critical': True}
    }
    
    # 可选依赖列表
    optional_modules = {
        'adb_shell': {'description': 'ADB连接库', 'critical': False},
        'yara': {'description': '病毒检测库', 'critical': False}
    }
    
    # PIL需要特殊处理
    pil_modules = {
        'PIL': {'description': '图像处理库', 'critical': False}
    }
    
    results = {
        'core_available': True,
        'missing_core': [],
        'missing_optional': [],
        'import_errors': {},
        'total_checked': 0,
        'available_count': 0
    }
    
    # 检查核心依赖
    for module, info in core_modules.items():
        results['total_checked'] += 1
        try:
            __import__(module)
            results['available_count'] += 1
            print(f"  ✅ {module} - {info['description']}")
        except ImportError as e:
            results['missing_core'].append(module)
            results['import_errors'][module] = str(e)
            results['core_available'] = False
            print(f"  ❌ {module} - {info['description']} (缺失)")
        except Exception as e:
            results['missing_core'].append(module)
            results['import_errors'][module] = f"加载异常: {str(e)}"
            results['core_available'] = False
            print(f"  ⚠️ {module} - {info['description']} (异常: {str(e)})")
    
    # 检查PIL（特殊处理）
    for module, info in pil_modules.items():
        results['total_checked'] += 1
        try:
            import PIL  # type: ignore
            results['available_count'] += 1
            print(f"  ✅ {module} - {info['description']} (可选)")
        except ImportError:
            results['missing_optional'].append(module)
            print(f"  ⚠️ {module} - {info['description']} (可选，未安装)")
        except Exception as e:
            results['missing_optional'].append(module)
            print(f"  ⚠️ {module} - {info['description']} (可选，异常: {str(e)})")
    
    # 检查可选依赖
    for module, info in optional_modules.items():
        results['total_checked'] += 1
        try:
            __import__(module)
            results['available_count'] += 1
            print(f"  ✅ {module} - {info['description']} (可选)")
        except ImportError:
            results['missing_optional'].append(module)
            print(f"  ⚠️ {module} - {info['description']} (可选，未安装)")
        except Exception as e:
            results['missing_optional'].append(module)
            print(f"  ⚠️ {module} - {info['description']} (可选，异常: {str(e)})")
    
    # 打印统计
    print(f"\n📊 依赖检查统计:")
    print(f"  总共检查: {results['total_checked']} 个模块")
    print(f"  可用模块: {results['available_count']} 个")
    print(f"  缺失核心模块: {len(results['missing_core'])} 个")
    print(f"  缺失可选模块: {len(results['missing_optional'])} 个")
    
    if not results['core_available']:
        print(f"\n❌ 核心依赖缺失: {', '.join(results['missing_core'])}")
        print("💡 修复建议: pip install -r requirements.txt")
        
        # 尝试自动修复
        auto_fix = input("\n是否尝试自动安装缺失的依赖？(y/N): ").lower().strip()
        if auto_fix == 'y':
            if install_dependencies():
                print("\n🔄 重新检查依赖...")
                return check_dependencies()
    
    return results

def install_dependencies() -> bool:
    """尝试自动安装依赖"""
    print("\n🔧 正在尝试自动安装依赖...")
    
    try:
        # 升级pip
        print("  📦 升级pip...")
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
            capture_output=True, text=True, timeout=60
        )
        
        if result.returncode == 0:
            print("  ✅ pip升级成功")
        else:
            print(f"  ⚠️ pip升级失败: {result.stderr}")
        
        # 安装requirements.txt
        requirements_file = project_root / 'requirements.txt'
        if requirements_file.exists():
            print("  📦 安装requirements.txt...")
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)],
                capture_output=True, text=True, timeout=300
            )
            
            if result.returncode == 0:
                print("  ✅ 依赖安装成功")
                return True
            else:
                print(f"  ❌ 依赖安装失败: {result.stderr}")
                return False
        else:
            print("  ❌ 未找到requirements.txt文件")
            return False
    
    except subprocess.TimeoutExpired:
        print("  ❌ 安装超时")
        return False
    except Exception as e:
        print(f"  ❌ 安装异常: {str(e)}")
        return False

def create_directories() -> bool:
    """创建必要的目录"""
    print("\n📁 正在创建目录结构...")
    
    directories = [
        'logs',
        'data',
        'data/virus_signatures',
        'data/system_resources',
        'data/quarantine',
        'backups',
        'cache/downloads'
    ]
    
    created_count = 0
    failed_count = 0
    
    for directory in directories:
        try:
            dir_path = Path(directory)
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # 验证目录创建成功
            if dir_path.exists() and dir_path.is_dir():
                print(f"  ✅ {directory}")
                created_count += 1
            else:
                print(f"  ❌ {directory} (创建失败)")
                failed_count += 1
                
        except PermissionError:
            print(f"  ❌ {directory} (权限不足)")
            failed_count += 1
        except Exception as e:
            print(f"  ❌ {directory} (异常: {str(e)})")
            failed_count += 1
    
    print(f"\n📊 目录创建统计: 成功 {created_count}/{len(directories)}")
    
    if failed_count > 0:
        print(f"⚠️ {failed_count} 个目录创建失败，可能影响程序功能")
    
    return failed_count == 0

def check_system_environment() -> Dict[str, Any]:
    """检查系统环境"""
    print("\n🖥️ 正在检查系统环境...")
    
    env_info = {
        'python_version': sys.version_info[:3],
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'working_directory': os.getcwd(),
        'project_root': str(project_root),
        'path_accessible': True,
        'permissions_ok': True
    }
    
    # 检查Python版本
    python_ok = sys.version_info[:2] >= (3, 8)
    print(f"  Python版本: {'✅' if python_ok else '❌'} {'.'.join(map(str, env_info['python_version']))}")
    
    # 检查平台
    supported_platforms = ['Windows', 'Linux', 'Darwin']
    platform_ok = env_info['platform'] in supported_platforms
    print(f"  操作系统: {'✅' if platform_ok else '⚠️'} {env_info['platform']} {env_info['platform_version']}")
    
    # 检查路径权限
    try:
        # 测试读取权限
        list(project_root.iterdir())
        print(f"  项目目录: ✅ {env_info['project_root']}")
        
        # 测试写入权限
        test_file = project_root / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
        print(f"  写入权限: ✅ 正常")
        
    except PermissionError:
        env_info['permissions_ok'] = False
        print(f"  项目目录: ❌ 权限不足")
    except Exception as e:
        env_info['path_accessible'] = False
        print(f"  项目目录: ❌ 访问异常: {str(e)}")
    
    env_info['system_ok'] = python_ok and platform_ok and env_info['permissions_ok']
    return env_info

def safe_import_modules():
    """安全导入核心模块"""
    print("\n📦 正在导入核心模块...")
    
    modules = {}
    errors = []
    
    try:
        print("  导入配置模块...")
        from src.config.settings import AppConfig
        modules['AppConfig'] = AppConfig
        print("  ✅ 配置模块")
    except Exception as e:
        errors.append(f"配置模块: {str(e)}")
        print(f"  ❌ 配置模块: {str(e)}")
    
    try:
        print("  导入主窗口模块...")
        from src.gui.main_window import MainWindow
        modules['MainWindow'] = MainWindow
        print("  ✅ 主窗口模块")
    except Exception as e:
        errors.append(f"主窗口模块: {str(e)}")
        print(f"  ❌ 主窗口模块: {str(e)}")
    
    try:
        print("  导入日志模块...")
        from src.utils.logger import setup_logger
        modules['setup_logger'] = setup_logger
        print("  ✅ 日志模块")
    except Exception as e:
        errors.append(f"日志模块: {str(e)}")
        print(f"  ❌ 日志模块: {str(e)}")
    
    if errors:
        print(f"\n❌ 模块导入失败({len(errors)}/{len(modules)+len(errors)}):")
        for error in errors:
            print(f"  • {error}")
        return None
    else:
        print(f"\n✅ 所有核心模块导入成功({len(modules)}/{len(modules)})")
        return modules

def main():
    """主函数"""
    start_time = time.time()
    
    print("=" * 80)
    print("🚀 Android系统修复工具启动器")
    print("版本: 1.0.0")
    print("=" * 80)
    
    # 解析命令行参数
    args = sys.argv[1:]
    diagnostic_mode = '--diagnostic' in args or '-d' in args
    verbose_mode = '--verbose' in args or '-v' in args
    
    if verbose_mode:
        logging.getLogger().setLevel(logging.DEBUG)
        print("🔍 详细模式已启用")
    
    try:
        # 1. 检查系统环境
        env_info = check_system_environment()
        if not env_info['system_ok']:
            print("\n⚠️ 系统环境检查发现问题，但将继续尝试启动")
        
        # 2. 检查/创建目录
        if not create_directories():
            print("\n⚠️ 部分目录创建失败，某些功能可能受限")
        
        # 3. 检查依赖
        dep_results = check_dependencies()
        if not dep_results['core_available']:
            print("\n❌ 核心依赖缺失，无法启动应用")
            print("💡 尝试运行: python start.py --diagnostic")
            sys.exit(1)
        
        # 4. 导入核心模块
        modules = safe_import_modules()
        if not modules:
            print("\n❌ 核心模块导入失败，无法启动应用")
            print("💡 请检查项目文件结构或运行: python start.py --diagnostic")
            sys.exit(1)
        
        # 5. 初始化应用
        print("\n⚙️ 正在初始化应用...")
        try:
            config = modules['AppConfig']()
            print("  ✅ 配置初始化成功")
            
            # 设置日志
            if 'setup_logger' in modules:
                modules['setup_logger'](config.log_level, config.log_file)
                print("  ✅ 日志系统初始化成功")
            
            logger.info("Android系统修复工具启动")
            logger.info(f"Python版本: {'.'.join(map(str, env_info['python_version']))}")
            logger.info(f"平台: {env_info['platform']}")
            
        except Exception as e:
            print(f"  ❌ 应用初始化失败: {str(e)}")
            logger.exception("应用初始化异常")
            sys.exit(1)
        
        # 6. 启动GUI
        print("\n🖼️ 正在启动图形界面...")
        try:
            app = modules['MainWindow'](config)
            
            # 检查是否有run方法
            if hasattr(app, 'run'):
                startup_time = time.time() - start_time
                print(f"✅ 启动成功 (用时 {startup_time:.2f}秒)")
                print("🎉 欢迎使用Android系统修复工具！")
                
                logger.info(f"GUI启动成功，用时 {startup_time:.2f}秒")
                app.run()
            else:
                raise AttributeError("MainWindow对象缺少run方法")
                
        except Exception as e:
            print(f"  ❌ GUI启动失败: {str(e)}")
            logger.exception("GUI启动异常")
            
            # 提供故障排除建议
            print("\n🔧 故障排除建议:")
            print("  1. 检查tkinter是否正确安装")
            print("  2. 确认在图形化环境中运行")
            print("  3. 尝试运行: python start.py --diagnostic")
            print("  4. 查看日志文件: logs/app.log")
            
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n⏹️ 用户中断启动")
        logger.info("用户中断启动")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 启动过程中发生意外错误: {str(e)}")
        logger.exception("启动异常")
        
        # 打印详细错误信息
        if verbose_mode:
            print("\n📋 详细错误信息:")
            traceback.print_exc()
        
        sys.exit(1)
    finally:
        logger.info("启动过程结束")

if __name__ == "__main__":
    # 显示启动帮助
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print("Android系统修复工具启动器")
        print("\n用法: python start.py [选项]")
        print("\n选项:")
        print("  -h, --help        显示此帮助信息")
        print("  -d, --diagnostic  运行详细诊断模式")
        print("  -v, --verbose     启用详细输出")
        print("\n示例:")
        print("  python start.py                    # 正常启动")
        print("  python start.py --diagnostic       # 诊断模式")
        print("  python start.py --verbose          # 详细输出")
        print("  python start.py -d -v              # 诊断+详细")
        sys.exit(0)
    
    main()