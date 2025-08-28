"""
智能启动器
支持多种启动模式，智能检测和修复启动问题
"""

import sys
import os
import argparse
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass
import logging

from .logger import setup_logger
from .exception_handler import get_exception_center, ExceptionSeverity
from .dependency_checker import DependencyChecker
from .config_validator import ConfigValidator


class StartupMode(Enum):
    """启动模式"""
    NORMAL = "normal"         # 普通模式
    DIAGNOSTIC = "diagnostic" # 诊断模式
    SAFE = "safe"            # 安全模式
    VERBOSE = "verbose"      # 详细模式
    CHECK_ONLY = "check"     # 仅检查模式


class StartupPhase(Enum):
    """启动阶段"""
    INIT = "init"                    # 初始化
    PRE_CHECK = "pre_check"          # 预启动检查
    DEPENDENCY_CHECK = "deps"        # 依赖检查
    CONFIG_CHECK = "config"          # 配置检查
    ENVIRONMENT_CHECK = "env"        # 环境检查
    MODULE_LOADING = "loading"       # 模块加载
    APPLICATION_START = "app_start"  # 应用启动
    COMPLETE = "complete"            # 启动完成


@dataclass
class StartupConfig:
    """启动配置"""
    mode: StartupMode = StartupMode.NORMAL
    log_level: str = "INFO"
    config_path: Optional[str] = None
    enable_auto_fix: bool = True
    enable_performance_monitor: bool = False
    minimal_ui: bool = False
    timeout: int = 120  # 启动超时时间（秒）


@dataclass
class CheckResult:
    """检查结果"""
    phase: StartupPhase
    success: bool
    message: str
    details: Dict[str, Any]
    fix_available: bool = False
    fix_action: Optional[Callable] = None


class IntelligentStarter:
    """智能启动器"""
    
    def __init__(self):
        self.logger = None  # 稍后初始化
        self.exception_center = get_exception_center()
        self.startup_config = StartupConfig()
        self.checkers: Dict[StartupPhase, Callable] = {}
        self.auto_fixers: Dict[StartupPhase, Callable] = {}
        self.startup_history: List[Dict] = []
        
        # 注册检查器
        self._register_checkers()
        
        # 注册自动修复器
        self._register_auto_fixers()
    
    def parse_arguments(self, args: Optional[List[str]] = None) -> StartupConfig:
        """
        解析启动参数
        
        Args:
            args: 命令行参数列表
            
        Returns:
            解析后的启动配置
        """
        parser = argparse.ArgumentParser(
            description="Android系统修复工具 - 智能启动器",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
启动模式说明：
  normal      普通启动模式（默认）
  diagnostic  诊断模式 - 执行详细的系统检查
  safe        安全模式 - 最小化功能启动
  verbose     详细模式 - 显示详细的调试信息
  check       仅检查模式 - 只执行检查不启动应用

使用示例：
  python main.py --mode diagnostic --verbose
  python main.py --mode safe --minimal-ui
  python main.py --check-deps --fix-missing
            """
        )
        
        parser.add_argument("--mode", "-m",
                           choices=[mode.value for mode in StartupMode],
                           default=StartupMode.NORMAL.value,
                           help="启动模式")
        
        parser.add_argument("--diagnostic", "-d",
                           action="store_true",
                           help="启用诊断模式（等同于 --mode diagnostic）")
        
        parser.add_argument("--safe", "-s",
                           action="store_true",
                           help="启用安全模式（等同于 --mode safe）")
        
        parser.add_argument("--verbose", "-v",
                           action="store_true",
                           help="启用详细输出")
        
        parser.add_argument("--log-level",
                           choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                           default="INFO",
                           help="日志级别")
        
        parser.add_argument("--config",
                           type=str,
                           help="配置文件路径")
        
        parser.add_argument("--no-auto-fix",
                           action="store_true",
                           help="禁用自动修复")
        
        parser.add_argument("--performance-monitor",
                           action="store_true",
                           help="启用性能监控")
        
        parser.add_argument("--minimal-ui",
                           action="store_true",
                           help="最小化UI界面")
        
        parser.add_argument("--timeout",
                           type=int,
                           default=120,
                           help="启动超时时间（秒）")
        
        parser.add_argument("--check-deps",
                           action="store_true",
                           help="检查依赖")
        
        parser.add_argument("--check-config",
                           action="store_true",
                           help="检查配置")
        
        parser.add_argument("--fix-missing",
                           action="store_true",
                           help="修复缺失的依赖和配置")
        
        parsed_args = parser.parse_args(args)
        
        # 构建启动配置
        config = StartupConfig()
        
        # 确定启动模式
        if parsed_args.diagnostic:
            config.mode = StartupMode.DIAGNOSTIC
        elif parsed_args.safe:
            config.mode = StartupMode.SAFE
        elif parsed_args.check_deps or parsed_args.check_config:
            config.mode = StartupMode.CHECK_ONLY
        else:
            config.mode = StartupMode(parsed_args.mode)
        
        # 设置其他配置
        if parsed_args.verbose or config.mode == StartupMode.VERBOSE:
            config.log_level = "DEBUG"
        else:
            config.log_level = parsed_args.log_level
        
        config.config_path = parsed_args.config
        config.enable_auto_fix = not parsed_args.no_auto_fix or parsed_args.fix_missing
        config.enable_performance_monitor = parsed_args.performance_monitor
        config.minimal_ui = parsed_args.minimal_ui
        config.timeout = parsed_args.timeout
        
        self.startup_config = config
        return config
    
    def start_application(self, main_func: Callable = None) -> bool:  # pyright: ignore[reportArgumentType]
        """
        启动应用程序
        
        Args:
            main_func: 主程序函数
            
        Returns:
            启动是否成功
        """
        start_time = time.time()
        
        try:
            # 初始化日志系统
            self._initialize_logging()
            
            self.logger.info("=" * 60)  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
            self.logger.info("Android系统修复工具 - 智能启动器")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
            self.logger.info(f"启动模式: {self.startup_config.mode.value}")  # pyright: ignore[reportOptionalMemberAccess]
            self.logger.info("=" * 60)  # pyright: ignore[reportOptionalMemberAccess]
            
            # 执行启动检查
            if not self._execute_startup_checks():
                self.logger.error("启动检查失败")  # pyright: ignore[reportOptionalMemberAccess]
                return False
            
            # 仅检查模式不启动应用
            if self.startup_config.mode == StartupMode.CHECK_ONLY:
                self.logger.info("检查完成，程序退出")  # pyright: ignore[reportOptionalMemberAccess]
                return True
            
            # 启动主应用
            if main_func:
                self.logger.info("启动主应用程序...")  # pyright: ignore[reportOptionalMemberAccess]
                
                # 安全模式下启用最小化功能
                if self.startup_config.mode == StartupMode.SAFE:
                    os.environ["SAFE_MODE"] = "1"
                
                # 启动应用的超时保护
                def start_with_timeout():
                    try:
                        return main_func()
                    except Exception as e:
                        self.exception_center.handle_exception(e, severity=ExceptionSeverity.HIGH)
                        return False
                
                if self.startup_config.timeout > 0:
                    import concurrent.futures
                    
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(start_with_timeout)
                        try:
                            result = future.result(timeout=self.startup_config.timeout)
                            success = result is not False
                        except concurrent.futures.TimeoutError:
                            self.logger.error(f"应用启动超时（{self.startup_config.timeout}秒）")  # pyright: ignore[reportOptionalMemberAccess]
                            success = False
                else:
                    success = start_with_timeout() is not False
            else:
                success = True
            
            # 记录启动历史
            elapsed_time = time.time() - start_time
            self._record_startup_history(success, elapsed_time)
            
            if success:
                self.logger.info(f"应用启动成功！耗时: {elapsed_time:.2f}秒")  # pyright: ignore[reportOptionalMemberAccess]
            else:
                self.logger.error(f"应用启动失败！耗时: {elapsed_time:.2f}秒")  # pyright: ignore[reportOptionalMemberAccess]
            
            return success
            
        except Exception as e:
            self.exception_center.handle_exception(e, severity=ExceptionSeverity.CRITICAL)
            return False
    
    def _initialize_logging(self):
        """初始化日志系统"""
        try:
            # 根据启动模式调整日志配置
            log_config = {
                "level": self.startup_config.log_level,
                "format": "colored" if self.startup_config.mode in [StartupMode.DIAGNOSTIC, StartupMode.VERBOSE] else "simple"
            }
            
            self.logger = setup_logger("IntelligentStarter", **log_config)  # pyright: ignore[reportArgumentType]
            
        except Exception as e:
            # 如果日志系统初始化失败，使用标准日志
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("IntelligentStarter")
            self.logger.error(f"日志系统初始化失败: {e}")
    
    def _execute_startup_checks(self) -> bool:
        """执行启动检查"""
        phases = [
            StartupPhase.PRE_CHECK,
            StartupPhase.DEPENDENCY_CHECK,
            StartupPhase.CONFIG_CHECK,
            StartupPhase.ENVIRONMENT_CHECK,
            StartupPhase.MODULE_LOADING
        ]
        
        for phase in phases:
            self.logger.info(f"执行检查: {phase.value}")  # pyright: ignore[reportOptionalMemberAccess]
            
            try:
                result = self._execute_phase_check(phase)
                
                if not result.success:
                    self.logger.warning(f"检查失败: {result.message}")  # pyright: ignore[reportOptionalMemberAccess]
                    
                    # 尝试自动修复
                    if self.startup_config.enable_auto_fix and result.fix_available:
                        self.logger.info("尝试自动修复...")  # pyright: ignore[reportOptionalMemberAccess]
                        if self._attempt_auto_fix(phase, result):
                            self.logger.info("自动修复成功，重新检查...")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                            result = self._execute_phase_check(phase)
                    
                    # 如果仍然失败
                    if not result.success:
                        if self.startup_config.mode == StartupMode.SAFE:
                            self.logger.warning("安全模式：忽略非关键错误")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                            continue
                        else:
                            self.logger.error("启动检查失败，无法继续")  # pyright: ignore[reportOptionalMemberAccess]
                            return False
                
                self.logger.info(f"✓ {phase.value} 检查通过")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                
            except Exception as e:
                self.logger.error(f"执行 {phase.value} 检查时发生异常: {e}")  # pyright: ignore[reportOptionalMemberAccess]
                self.exception_center.handle_exception(e)
                
                if self.startup_config.mode != StartupMode.SAFE:
                    return False
        
        return True
    
    def _execute_phase_check(self, phase: StartupPhase) -> CheckResult:
        """执行特定阶段的检查"""
        if phase in self.checkers:
            try:
                return self.checkers[phase]()
            except Exception as e:
                return CheckResult(
                    phase=phase,
                    success=False,
                    message=f"检查器执行异常: {e}",
                    details={"exception": str(e)}
                )
        else:
            return CheckResult(
                phase=phase,
                success=True,
                message="无需检查",
                details={}
            )
    
    def _attempt_auto_fix(self, phase: StartupPhase, check_result: CheckResult) -> bool:
        """尝试自动修复"""
        try:
            if phase in self.auto_fixers:
                fixer = self.auto_fixers[phase]
                return fixer(check_result)
            elif check_result.fix_action:
                return check_result.fix_action()
            else:
                return False
        except Exception as e:
            self.logger.error(f"自动修复失败: {e}")  # pyright: ignore[reportOptionalMemberAccess]
            self.exception_center.handle_exception(e)
            return False
    
    def _register_checkers(self):
        """注册检查器"""
        
        def pre_check() -> CheckResult:
            """预启动检查"""
            issues = []
            
            # 检查Python版本
            if sys.version_info < (3, 8):
                issues.append(f"Python版本过低: {sys.version}, 需要 >= 3.8")
            
            # 检查基本权限
            if os.name == 'nt':  # Windows
                try:
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                    if not is_admin:
                        issues.append("建议以管理员权限运行")
                except:
                    pass
            
            return CheckResult(
                phase=StartupPhase.PRE_CHECK,
                success=len(issues) == 0,
                message="; ".join(issues) if issues else "预检查通过",
                details={"issues": issues}
            )
        
        def dependency_check() -> CheckResult:
            """依赖检查"""
            try:
                checker = DependencyChecker()
                result = checker.check_all_dependencies()  # pyright: ignore[reportAttributeAccessIssue]
                
                return CheckResult(
                    phase=StartupPhase.DEPENDENCY_CHECK,
                    success=result.get("all_passed", False),
                    message=result.get("summary", "依赖检查完成"),
                    details=result,
                    fix_available=len(result.get("missing_packages", [])) > 0
                )
            except Exception as e:
                return CheckResult(
                    phase=StartupPhase.DEPENDENCY_CHECK,
                    success=False,
                    message=f"依赖检查失败: {e}",
                    details={"error": str(e)}
                )
        
        def config_check() -> CheckResult:
            """配置检查"""
            try:
                validator = ConfigValidator()
                config_path = self.startup_config.config_path or "config.ini"
                result = validator.validate_config(config_path)  # pyright: ignore[reportArgumentType]
                
                return CheckResult(
                    phase=StartupPhase.CONFIG_CHECK,
                    success=result.get("valid", False),  # pyright: ignore[reportAttributeAccessIssue]
                    message=result.get("message", "配置检查完成"),  # pyright: ignore[reportAttributeAccessIssue]
                    details=result,  # pyright: ignore[reportArgumentType]
                    fix_available=not result.get("valid", True)  # pyright: ignore[reportAttributeAccessIssue]
                )
            except Exception as e:
                return CheckResult(
                    phase=StartupPhase.CONFIG_CHECK,
                    success=False,
                    message=f"配置检查失败: {e}",
                    details={"error": str(e)},
                    fix_available=True
                )
        
        def environment_check() -> CheckResult:
            """环境检查"""
            issues = []
            
            # 检查ADB
            adb_found = False
            try:
                import subprocess
                result = subprocess.run(['adb', 'version'], 
                                      capture_output=True, text=True, timeout=10)
                adb_found = result.returncode == 0
            except:
                pass
            
            if not adb_found:
                issues.append("ADB工具未找到或不可用")
            
            # 检查必要目录
            required_dirs = ['logs', 'data', 'backups']
            for dir_name in required_dirs:
                if not os.path.exists(dir_name):
                    issues.append(f"缺少目录: {dir_name}")
            
            return CheckResult(
                phase=StartupPhase.ENVIRONMENT_CHECK,
                success=len(issues) == 0,
                message="; ".join(issues) if issues else "环境检查通过",
                details={"issues": issues, "adb_available": adb_found},
                fix_available=len(issues) > 0
            )
        
        def module_loading_check() -> CheckResult:
            """模块加载检查"""
            try:
                # 尝试导入关键模块
                critical_modules = [
                    'src.core.device_manager',
                    'src.gui.main_window',
                    'src.config.settings'
                ]
                
                issues = []
                for module_name in critical_modules:
                    try:
                        __import__(module_name)
                    except ImportError as e:
                        issues.append(f"无法导入 {module_name}: {e}")
                
                return CheckResult(
                    phase=StartupPhase.MODULE_LOADING,
                    success=len(issues) == 0,
                    message="; ".join(issues) if issues else "模块加载检查通过",
                    details={"issues": issues}
                )
            except Exception as e:
                return CheckResult(
                    phase=StartupPhase.MODULE_LOADING,
                    success=False,
                    message=f"模块加载检查失败: {e}",
                    details={"error": str(e)}
                )
        
        # 注册检查器
        self.checkers[StartupPhase.PRE_CHECK] = pre_check
        self.checkers[StartupPhase.DEPENDENCY_CHECK] = dependency_check
        self.checkers[StartupPhase.CONFIG_CHECK] = config_check
        self.checkers[StartupPhase.ENVIRONMENT_CHECK] = environment_check
        self.checkers[StartupPhase.MODULE_LOADING] = module_loading_check
    
    def _register_auto_fixers(self):
        """注册自动修复器"""
        
        def fix_dependencies(check_result: CheckResult) -> bool:
            """修复依赖问题"""
            try:
                missing_packages = check_result.details.get("missing_packages", [])
                if not missing_packages:
                    return True
                
                self.logger.info(f"尝试安装缺失的包: {missing_packages}")  # pyright: ignore[reportOptionalMemberAccess]
                
                import subprocess
                for package in missing_packages:
                    try:
                        result = subprocess.run(
                            [sys.executable, "-m", "pip", "install", package],
                            capture_output=True, text=True, timeout=60
                        )
                        if result.returncode == 0:
                            self.logger.info(f"✓ 成功安装: {package}")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                        else:
                            self.logger.error(f"✗ 安装失败: {package}")  # pyright: ignore[reportOptionalMemberAccess]
                            return False
                    except subprocess.TimeoutExpired:
                        self.logger.error(f"安装 {package} 超时")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                        return False
                
                return True
            except Exception as e:
                self.logger.error(f"依赖修复失败: {e}")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                return False
        
        def fix_config(check_result: CheckResult) -> bool:
            """修复配置问题"""
            try:
                validator = ConfigValidator()
                config_path = self.startup_config.config_path or "config.ini"
                
                # 尝试创建默认配置
                if not os.path.exists(config_path):
                    default_config = validator.create_default_config()
                    with open(config_path, 'w', encoding='utf-8') as f:
                        default_config.write(f)
                    self.logger.info(f"创建默认配置文件: {config_path}")  # pyright: ignore[reportOptionalMemberAccess]  # pyright: ignore[reportOptionalMemberAccess]
                    return True
                
                # 尝试修复损坏的配置
                return validator.fix_config_file(config_path)  # pyright: ignore[reportAttributeAccessIssue]  # pyright: ignore[reportAttributeAccessIssue]
            except Exception as e:
                self.logger.error(f"配置修复失败: {e}")  # pyright: ignore[reportOptionalMemberAccess]
                return False
        
        def fix_environment(check_result: CheckResult) -> bool:
            """修复环境问题"""
            try:
                issues = check_result.details.get("issues", [])
                
                # 创建缺失的目录
                for issue in issues:
                    if issue.startswith("缺少目录:"):
                        dir_name = issue.split(":")[1].strip()
                        try:
                            os.makedirs(dir_name, exist_ok=True)
                            self.logger.info(f"创建目录: {dir_name}")  # pyright: ignore[reportOptionalMemberAccess]
                        except Exception as e:
                            self.logger.error(f"创建目录失败 {dir_name}: {e}")  # pyright: ignore[reportOptionalMemberAccess]
                            return False
                
                return True
            except Exception as e:
                self.logger.error(f"环境修复失败: {e}")  # pyright: ignore[reportOptionalMemberAccess]
                return False
        
        # 注册修复器
        self.auto_fixers[StartupPhase.DEPENDENCY_CHECK] = fix_dependencies
        self.auto_fixers[StartupPhase.CONFIG_CHECK] = fix_config
        self.auto_fixers[StartupPhase.ENVIRONMENT_CHECK] = fix_environment
    
    def _record_startup_history(self, success: bool, elapsed_time: float):
        """记录启动历史"""
        record = {
            "timestamp": time.time(),
            "mode": self.startup_config.mode.value,
            "success": success,
            "elapsed_time": elapsed_time,
            "log_level": self.startup_config.log_level
        }
        
        self.startup_history.append(record)
        
        # 限制历史记录数量
        if len(self.startup_history) > 100:
            self.startup_history = self.startup_history[-50:]
    
    def get_startup_statistics(self) -> Dict[str, Any]:
        """获取启动统计信息"""
        if not self.startup_history:
            return {"total": 0}
        
        total = len(self.startup_history)
        successful = sum(1 for record in self.startup_history if record["success"])
        failed = total - successful
        
        avg_time = sum(record["elapsed_time"] for record in self.startup_history) / total
        
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total * 100,
            "average_time": avg_time,
            "recent": self.startup_history[-10:]
        }


# 全局智能启动器实例
_global_starter = None
_starter_lock = threading.Lock()


def get_intelligent_starter() -> IntelligentStarter:
    """获取全局智能启动器实例"""
    global _global_starter
    if _global_starter is None:
        with _starter_lock:
            if _global_starter is None:
                _global_starter = IntelligentStarter()
    return _global_starter


def smart_start(main_func: Callable = None, args: List[str] = None) -> bool:  # pyright: ignore[reportArgumentType]
    """
    智能启动入口函数
    
    Args:
        main_func: 主程序函数
        args: 命令行参数
        
    Returns:
        启动是否成功
    """
    starter = get_intelligent_starter()
    
    # 解析参数
    starter.parse_arguments(args)
    
    # 启动应用
    return starter.start_application(main_func)