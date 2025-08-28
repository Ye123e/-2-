#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具 - 智能启动脚本
集成异常处理、自动修复、诊断工具的全面启动解决方案
"""

import sys
import os
import traceback
import time
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.utils.intelligent_starter import smart_start, get_intelligent_starter
    from src.utils.exception_handler import get_exception_center, ExceptionSeverity
    from src.utils.auto_repair_manager import get_auto_repair_manager, Problem, ProblemType
    from src.utils.diagnostic_tools import DiagnosticRunner
    from src.utils.logger import setup_logger
except ImportError as e:
    print(f"❌ 导入核心模块失败: {e}")
    print("🔧 请检查项目依赖是否正确安装")
    sys.exit(1)


def recovery_callback(issue):
    """异常恢复回调函数"""
    logger = setup_logger("RecoveryCallback")
    
    if isinstance(issue, dict) and issue.get('type') == 'high_error_rate':
        logger.warning("检测到高错误率，启动自动恢复...")
        
        # 分析最近的错误
        recent_errors = issue.get('recent_errors', [])
        error_types = {}
        
        for error in recent_errors:
            module = error.get('module', 'unknown')
            error_types[module] = error_types.get(module, 0) + 1
        
        logger.info(f"错误分布: {error_types}")
        
        # 尝试重启问题模块
        for module, count in error_types.items():
            if count > 3:  # 同一模块错误超过3次
                logger.info(f"尝试重新初始化模块: {module}")
                # 这里可以添加模块重启逻辑
    
    elif hasattr(issue, 'levelname') and issue.levelname == 'CRITICAL':
        logger.critical(f"严重异常: {issue.getMessage()}")
        # 记录崩溃信息
        crash_info = {
            'timestamp': time.time(),
            'message': issue.getMessage(),
            'module': getattr(issue, 'module', 'unknown')
        }
        
        # 保存崩溃日志
        try:
            import json
            crash_file = project_root / "logs" / f"crash_{int(time.time())}.json"
            crash_file.parent.mkdir(exist_ok=True)
            
            with open(crash_file, 'w', encoding='utf-8') as f:
                json.dump(crash_info, f, indent=2, ensure_ascii=False)
            
            logger.info(f"崩溃信息已保存到: {crash_file}")
        except Exception as e:
            logger.error(f"保存崩溃信息失败: {e}")


def run_pre_startup_diagnostics():
    """运行启动前诊断"""
    print("🔍 执行启动前诊断...")
    
    try:
        runner = DiagnosticRunner()
        
        # 只运行关键诊断
        critical_diagnostics = ["python", "system"]
        results = runner.run_specific(critical_diagnostics, "text")
        
        # 检查是否有严重问题
        diagnostics = results.get("diagnostics", {})
        critical_issues = []
        
        for name, result in diagnostics.items():
            if result.get("status") == "fail":
                critical_issues.append(f"{name}: {result.get('message', 'Unknown error')}")
        
        if critical_issues:
            print("❌ 发现严重问题:")
            for issue in critical_issues:
                print(f"   • {issue}")
            
            # 询问是否继续
            response = input("\n⚠️ 是否尝试自动修复? (y/N): ").lower()
            if response in ['y', 'yes']:
                return attempt_auto_repair(diagnostics)
            else:
                print("❌ 用户选择不修复，程序退出")
                return False
        else:
            print("✅ 启动前诊断通过")
            return True
            
    except Exception as e:
        print(f"❌ 诊断失败: {e}")
        return True  # 诊断失败时仍然尝试启动


def attempt_auto_repair(diagnostic_results):
    """尝试自动修复问题"""
    print("🔧 启动自动修复...")
    
    try:
        repair_manager = get_auto_repair_manager()
        problems = []
        
        # 分析诊断结果，生成问题列表
        for name, result in diagnostic_results.items():
            if result.get("status") in ["fail", "error"]:
                details = result.get("details", {})
                
                if name == "python":
                    # Python环境问题
                    if "pip未安装" in result.get("message", ""):
                        problems.append(Problem(
                            problem_type=ProblemType.DEPENDENCY_MISSING,
                            severity=8,
                            description="pip包管理器缺失",
                            details={"missing_packages": ["pip"]},
                            fix_priority=9
                        ))
                elif name == "system":
                    # 系统资源问题  
                    if "内存" in result.get("message", ""):
                        problems.append(Problem(
                            problem_type=ProblemType.MEMORY_INSUFFICIENT,
                            severity=7,
                            description="系统内存不足",
                            details=details,
                            fix_priority=6,
                            auto_fixable=False  # 内存问题通常无法自动修复
                        ))
                    elif "磁盘" in result.get("message", ""):
                        problems.append(Problem(
                            problem_type=ProblemType.DISK_SPACE_LOW,
                            severity=6,
                            description="磁盘空间不足", 
                            details=details,
                            fix_priority=7
                        ))
        
        if not problems:
            print("✅ 未发现可修复的问题")
            return True
        
        # 执行修复
        repair_results = repair_manager.diagnose_and_repair(problems)
        
        if repair_results.get("successful", 0) > 0:
            print(f"✅ 成功修复 {repair_results['successful']} 个问题")
            return True
        else:
            print(f"❌ 修复失败，{repair_results['failed']} 个问题未解决")
            return False
            
    except Exception as e:
        print(f"❌ 自动修复失败: {e}")
        return False


def main_application():
    """主应用程序入口"""
    try:
        # 导入主程序
        from main import main as app_main
        
        # 启动主程序
        print("🚀 启动主应用程序...")
        return app_main()
        
    except ImportError as e:
        print(f"❌ 无法导入主程序: {e}")
        return False
    except Exception as e:
        print(f"❌ 主程序启动失败: {e}")
        print(f"详细错误: {traceback.format_exc()}")
        return False


def emergency_mode():
    """应急模式"""
    print("\n" + "="*60)
    print("🚨 进入应急模式")
    print("="*60)
    
    print("\n可用操作:")
    print("1. 运行系统诊断")
    print("2. 查看错误日志")
    print("3. 重置配置文件")
    print("4. 检查依赖")
    print("5. 退出")
    
    while True:
        try:
            choice = input("\n请选择操作 (1-5): ").strip()
            
            if choice == "1":
                runner = DiagnosticRunner()
                runner.run_all("text")
                
            elif choice == "2":
                log_file = project_root / "logs" / "app.log"
                if log_file.exists():
                    print(f"\n📄 日志文件: {log_file}")
                    # 显示最后50行
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            for line in lines[-50:]:
                                print(line.rstrip())
                    except Exception as e:
                        print(f"读取日志失败: {e}")
                else:
                    print("❌ 日志文件不存在")
                    
            elif choice == "3":
                config_file = project_root / "config.ini"
                if config_file.exists():
                    backup_file = project_root / f"config.ini.backup.{int(time.time())}"
                    import shutil
                    shutil.copy2(config_file, backup_file)
                    print(f"✅ 配置文件已备份到: {backup_file}")
                
                # 创建默认配置
                try:
                    from src.utils.config_validator import ConfigValidator
                    validator = ConfigValidator()
                    default_config = validator.create_default_config()
                    
                    with open(config_file, 'w', encoding='utf-8') as f:
                        default_config.write(f)
                    
                    print(f"✅ 已重置配置文件: {config_file}")
                except Exception as e:
                    print(f"❌ 重置配置失败: {e}")
                    
            elif choice == "4":
                try:
                    from src.utils.dependency_checker import DependencyChecker
                    checker = DependencyChecker()
                    result = checker.check_all_dependencies()
                    
                    print("\n依赖检查结果:")
                    print(f"Python版本: {result.get('python_version', 'Unknown')}")
                    
                    missing = result.get('missing_packages', [])
                    if missing:
                        print(f"❌ 缺失包: {missing}")
                    else:
                        print("✅ 所有依赖包已安装")
                        
                except Exception as e:
                    print(f"❌ 依赖检查失败: {e}")
                    
            elif choice == "5":
                print("👋 退出应急模式")
                break
                
            else:
                print("❌ 无效选择，请输入 1-5")
                
        except KeyboardInterrupt:
            print("\n👋 退出应急模式")
            break
        except Exception as e:
            print(f"❌ 操作失败: {e}")


def main():
    """主入口函数"""
    print("=" * 60)
    print("🤖 Android系统修复工具 - 智能启动器")
    print("=" * 60)
    
    # 初始化异常处理中心
    exception_center = get_exception_center()
    
    # 注册崩溃恢复处理器
    try:
        from src.utils.logger import CrashRecoveryHandler
        crash_handler = CrashRecoveryHandler(recovery_callback)
        logger = setup_logger("IntelligentStarter")
        logger.addHandler(crash_handler)
    except Exception as e:
        print(f"⚠️ 崩溃恢复处理器注册失败: {e}")
    
    try:
        # 运行启动前诊断
        if not run_pre_startup_diagnostics():
            print("\n❌ 启动前检查失败")
            emergency_mode()
            return 1
        
        # 使用智能启动器启动应用
        success = smart_start(main_application)
        
        if success:
            print("\n✅ 应用程序成功启动并退出")
            return 0
        else:
            print("\n❌ 应用程序启动失败")
            
            # 询问是否进入应急模式
            try:
                response = input("🚨 是否进入应急模式? (y/N): ").lower()
                if response in ['y', 'yes']:
                    emergency_mode()
            except KeyboardInterrupt:
                pass
            
            return 1
            
    except KeyboardInterrupt:
        print("\n\n👋 用户中断，程序退出")
        return 0
    except Exception as e:
        print(f"\n💥 未处理的异常: {e}")
        print(f"详细信息: {traceback.format_exc()}")
        
        # 记录异常到异常处理中心
        exception_center.handle_exception(e, severity=ExceptionSeverity.CRITICAL)
        
        # 进入应急模式
        try:
            response = input("\n🚨 是否进入应急模式? (y/N): ").lower()
            if response in ['y', 'yes']:
                emergency_mode()
        except:
            pass
        
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)