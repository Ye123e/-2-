#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android系统修复工具闪退问题修复 - 综合测试
测试所有闪退修复相关功能
"""

import sys
import os
import unittest
import tempfile
import shutil
import time
import threading
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from src.utils.exception_handler import (
        ExceptionHandlingCenter, ExceptionSeverity, RecoveryAction,
        get_exception_center, exception_handler, safe_execute
    )
    from src.utils.intelligent_starter import (
        IntelligentStarter, StartupMode, StartupConfig,
        get_intelligent_starter, smart_start
    )
    from src.utils.auto_repair_manager import (
        AutoRepairManager, ProblemType, RepairStatus, Problem,
        DependencyRepairer, ConfigRepairer, get_auto_repair_manager
    )
    from src.utils.diagnostic_tools import (
        DiagnosticRunner, PythonEnvironmentDiagnostic, 
        SystemResourceDiagnostic, NetworkConnectivityDiagnostic
    )
    from src.utils.logger import (
        ColoredFormatter, JSONFormatter, BufferedFileHandler,
        CrashRecoveryHandler, PerformanceMetricsHandler, setup_logger
    )
except ImportError as e:
    print(f"❌ 导入测试模块失败: {e}")
    sys.exit(1)


class TestExceptionHandlingCenter(unittest.TestCase):
    """测试异常处理中心"""
    
    def setUp(self):
        self.center = ExceptionHandlingCenter()
    
    def test_singleton_pattern(self):
        """测试单例模式"""
        center1 = get_exception_center()
        center2 = get_exception_center()
        self.assertIs(center1, center2)
    
    def test_exception_registration(self):
        """测试异常处理器注册"""
        def test_handler(exc):
            return True
        
        self.center.register_handler(ValueError, test_handler)
        
        # 测试异常处理
        test_exception = ValueError("test error")
        result = self.center.handle_exception(test_exception)
        self.assertTrue(result)
    
    def test_exception_statistics(self):
        """测试异常统计"""
        # 模拟一些异常
        exceptions = [
            ValueError("test1"),
            TypeError("test2"), 
            RuntimeError("test3")
        ]
        
        for exc in exceptions:
            self.center.handle_exception(exc)
        
        stats = self.center.get_exception_statistics()
        self.assertEqual(stats["total"], 3)
        self.assertIn("by_type", stats)
    
    def test_exception_decorator(self):
        """测试异常处理装饰器"""
        @exception_handler(severity=ExceptionSeverity.LOW)
        def test_function():
            raise ValueError("test error")
        
        # 应该不会抛出异常
        result = test_function()
        self.assertIsNone(result)
    
    def test_safe_execute(self):
        """测试安全执行"""
        def failing_function():
            raise ValueError("test error")
        
        def working_function():
            return "success"
        
        # 测试失败函数
        result = safe_execute(failing_function, default_return="failed")
        self.assertEqual(result, "failed")
        
        # 测试成功函数
        result = safe_execute(working_function)
        self.assertEqual(result, "success")


class TestIntelligentStarter(unittest.TestCase):
    """测试智能启动器"""
    
    def setUp(self):
        self.starter = IntelligentStarter()
    
    def test_argument_parsing(self):
        """测试参数解析"""
        # 测试诊断模式
        config = self.starter.parse_arguments(["--diagnostic", "--verbose"])
        self.assertEqual(config.mode, StartupMode.DIAGNOSTIC)
        self.assertEqual(config.log_level, "DEBUG")
        
        # 测试安全模式
        config = self.starter.parse_arguments(["--safe", "--minimal-ui"])
        self.assertEqual(config.mode, StartupMode.SAFE)
        self.assertTrue(config.minimal_ui)
    
    def test_startup_phases(self):
        """测试启动阶段"""
        # 模拟成功的检查
        with patch.object(self.starter, '_execute_phase_check') as mock_check:
            mock_check.return_value = Mock(success=True, message="OK", details={})
            
            result = self.starter._execute_startup_checks()
            self.assertTrue(result)
    
    def test_auto_fix_mechanism(self):
        """测试自动修复机制"""
        # 创建一个需要修复的检查结果
        check_result = Mock()
        check_result.success = False
        check_result.fix_available = True
        check_result.fix_action = Mock(return_value=True)
        
        result = self.starter._attempt_auto_fix(None, check_result)
        self.assertTrue(result)
        check_result.fix_action.assert_called_once()
    
    def test_startup_history(self):
        """测试启动历史记录"""
        # 记录一些启动历史
        self.starter._record_startup_history(True, 2.5)
        self.starter._record_startup_history(False, 1.8)
        
        stats = self.starter.get_startup_statistics()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["successful"], 1)
        self.assertEqual(stats["failed"], 1)


class TestAutoRepairManager(unittest.TestCase):
    """测试自动修复管理器"""
    
    def setUp(self):
        self.manager = AutoRepairManager()
    
    def test_repairer_registration(self):
        """测试修复器注册"""
        repairer = DependencyRepairer()
        self.manager.register_repairer(ProblemType.DEPENDENCY_MISSING, repairer)
        
        # 验证注册
        repairers = self.manager.repairers.get(ProblemType.DEPENDENCY_MISSING, [])
        self.assertIn(repairer, repairers)
    
    def test_repair_plan_creation(self):
        """测试修复计划创建"""
        problems = [
            Problem(
                problem_type=ProblemType.CONFIG_INVALID,
                severity=5,
                description="配置文件损坏",
                auto_fixable=True
            ),
            Problem(
                problem_type=ProblemType.DEPENDENCY_MISSING,
                severity=8,
                description="缺少依赖包", 
                auto_fixable=True
            )
        ]
        
        repair_plan = self.manager.create_repair_plan(problems)
        self.assertEqual(len(repair_plan), 2)
        
        # 验证按优先级排序
        self.assertGreaterEqual(repair_plan[0].problem.severity, repair_plan[1].problem.severity)
    
    def test_dependency_repairer(self):
        """测试依赖修复器"""
        repairer = DependencyRepairer()
        
        problem = Problem(
            problem_type=ProblemType.DEPENDENCY_MISSING,
            severity=5,
            description="缺少包",
            details={"missing_packages": ["fake-package-for-test"]}
        )
        
        # 测试是否可以修复
        self.assertTrue(repairer.can_repair(problem))
        
        # 测试时间估算
        estimated_time = repairer.estimate_time(problem)
        self.assertGreater(estimated_time, 0)
    
    def test_config_repairer(self):
        """测试配置修复器"""
        repairer = ConfigRepairer()
        
        problem = Problem(
            problem_type=ProblemType.CONFIG_INVALID,
            severity=3,
            description="配置无效",
            details={"config_path": "test_config.ini"}
        )
        
        self.assertTrue(repairer.can_repair(problem))
        
        # 测试修复执行（需要模拟）
        with tempfile.NamedTemporaryFile(suffix=".ini", delete=False) as f:
            problem.details["config_path"] = f.name
            
            with patch('src.utils.config_validator.ConfigValidator') as mock_validator:
                mock_config = Mock()
                mock_validator.return_value.create_default_config.return_value = mock_config
                
                result = repairer.execute(problem)
                self.assertTrue(result.get("success", False))
            
            # 清理
            os.unlink(f.name)


class TestDiagnosticTools(unittest.TestCase):
    """测试诊断工具"""
    
    def test_python_environment_diagnostic(self):
        """测试Python环境诊断"""
        diagnostic = PythonEnvironmentDiagnostic()
        result = diagnostic.check()
        
        self.assertIsNotNone(result.checker_name)
        self.assertIn(result.status.value, ["pass", "warning", "fail", "error"])
        self.assertIsInstance(result.details, dict)
        self.assertIn("python_version", result.details)
    
    def test_system_resource_diagnostic(self):
        """测试系统资源诊断"""
        diagnostic = SystemResourceDiagnostic()
        result = diagnostic.check()
        
        self.assertIsNotNone(result.message)
        self.assertIsInstance(result.suggestions, list)
    
    def test_diagnostic_runner(self):
        """测试诊断运行器"""
        runner = DiagnosticRunner()
        
        # 测试运行所有诊断
        results = runner.run_all("json")
        
        self.assertIn("diagnostics", results)
        self.assertIn("summary", results)
        
        summary = results["summary"]
        self.assertIn("total", summary)
        self.assertIn("passed", summary)
        self.assertIn("warnings", summary)
        self.assertIn("failed", summary)
    
    def test_standalone_diagnostic(self):
        """测试独立诊断工具"""
        diagnostic = PythonEnvironmentDiagnostic()
        
        # 重定向输出测试
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            output = diagnostic.run_standalone("json")
        
        self.assertIn("checker", output)
        self.assertIn("result", output)


class TestLoggerEnhancements(unittest.TestCase):
    """测试日志系统增强"""
    
    def test_colored_formatter(self):
        """测试彩色格式化器"""
        formatter = ColoredFormatter()
        
        import logging
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="test message", args=(), exc_info=None
        )
        
        formatted = formatter.format(record)
        self.assertIn("test message", formatted)
    
    def test_json_formatter(self):
        """测试JSON格式化器"""
        formatter = JSONFormatter()
        
        import logging
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=1,
            msg="test error", args=(), exc_info=None
        )
        
        formatted = formatter.format(record)
        data = json.loads(formatted)
        
        self.assertEqual(data["level"], "ERROR")
        self.assertEqual(data["message"], "test error")
        self.assertIn("timestamp", data)
    
    def test_crash_recovery_handler(self):
        """测试崩溃恢复处理器"""
        recovery_calls = []
        
        def test_recovery_callback(issue):
            recovery_calls.append(issue)
        
        handler = CrashRecoveryHandler(test_recovery_callback)
        
        # 模拟严重错误
        import logging
        critical_record = logging.LogRecord(
            name="test", level=logging.CRITICAL, pathname="", lineno=1,
            msg="critical error", args=(), exc_info=None
        )
        
        handler.emit(critical_record)
        
        self.assertEqual(handler.critical_count, 1)
        self.assertEqual(len(recovery_calls), 1)
    
    def test_performance_metrics_handler(self):
        """测试性能指标处理器"""
        handler = PerformanceMetricsHandler()
        
        import logging
        
        # 模拟不同级别的日志
        for level in [logging.INFO, logging.WARNING, logging.ERROR]:
            record = logging.LogRecord(
                name="test", level=level, pathname="", lineno=1,
                msg="test message", args=(), exc_info=None
            )
            handler.emit(record)
        
        stats = handler.get_performance_stats()
        self.assertIn("log_count_by_level", stats)
        self.assertIn("uptime", stats)
        
        # 检查级别统计
        level_counts = stats["log_count_by_level"]
        self.assertEqual(level_counts.get("INFO", 0), 1)
        self.assertEqual(level_counts.get("WARNING", 0), 1)
        self.assertEqual(level_counts.get("ERROR", 0), 1)


class TestIntegrationScenarios(unittest.TestCase):
    """测试集成场景"""
    
    def test_startup_with_dependency_issues(self):
        """测试启动时依赖问题的处理"""
        starter = IntelligentStarter()
        
        # 模拟依赖检查失败
        def mock_dependency_check():
            from src.utils.intelligent_starter import CheckResult, StartupPhase
            return CheckResult(
                phase=StartupPhase.DEPENDENCY_CHECK,
                success=False,
                message="缺少依赖包",
                details={"missing_packages": ["test-package"]},
                fix_available=True
            )
        
        starter.checkers[starter.checkers.__iter__().__next__()] = mock_dependency_check
        
        # 测试自动修复
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            
            starter.startup_config.enable_auto_fix = True
            result = starter._execute_startup_checks()
            
            # 在启用自动修复的情况下应该成功
            self.assertTrue(result)
    
    def test_crash_recovery_workflow(self):
        """测试崩溃恢复工作流"""
        # 模拟崩溃场景
        exception_center = get_exception_center()
        
        recovery_actions = []
        
        def mock_recovery(action_name, **kwargs):
            recovery_actions.append((action_name, kwargs))
            return True
        
        exception_center.execute_recovery = mock_recovery
        
        # 触发严重异常
        critical_exception = RuntimeError("Critical system error")
        
        handled = exception_center.handle_exception(
            critical_exception, 
            severity=ExceptionSeverity.CRITICAL
        )
        
        # 验证异常被记录
        stats = exception_center.get_exception_statistics()
        self.assertGreater(stats["total"], 0)
    
    def test_end_to_end_smart_start(self):
        """测试端到端智能启动"""
        def mock_main_app():
            return True
        
        # 测试成功启动场景
        with patch('src.utils.intelligent_starter.DependencyChecker') as mock_checker:
            mock_checker.return_value.check_all_dependencies.return_value = {
                "all_passed": True,
                "summary": "All dependencies OK"
            }
            
            with patch('src.utils.intelligent_starter.ConfigValidator') as mock_validator:
                mock_validator.return_value.validate_config.return_value = {
                    "valid": True,
                    "message": "Config is valid"
                }
                
                # 执行智能启动
                success = smart_start(mock_main_app, ["--mode", "normal"])
                self.assertTrue(success)


class TestPerformanceAndStability(unittest.TestCase):
    """测试性能和稳定性"""
    
    def test_exception_handler_performance(self):
        """测试异常处理器性能"""
        center = ExceptionHandlingCenter()
        
        # 大量异常处理测试
        start_time = time.time()
        
        for i in range(1000):
            try:
                raise ValueError(f"Test exception {i}")
            except ValueError as e:
                center.handle_exception(e)
        
        elapsed = time.time() - start_time
        
        # 应该在合理时间内完成（比如5秒）
        self.assertLess(elapsed, 5.0)
        
        # 验证所有异常都被记录
        stats = center.get_exception_statistics()
        self.assertEqual(stats["total"], 1000)
    
    def test_concurrent_logging(self):
        """测试并发日志记录"""
        logger = setup_logger("ConcurrentTest")
        
        def log_worker(worker_id):
            for i in range(100):
                logger.info(f"Worker {worker_id} - Message {i}")
        
        # 启动多个线程
        threads = []
        for worker_id in range(10):
            thread = threading.Thread(target=log_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        # 测试完成，没有崩溃就是成功
        self.assertTrue(True)
    
    def test_memory_usage_stability(self):
        """测试内存使用稳定性"""
        import gc
        
        # 获取初始内存使用
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # 执行一些操作
        for i in range(100):
            starter = IntelligentStarter()
            manager = AutoRepairManager()
            runner = DiagnosticRunner()
            
            # 模拟一些操作
            starter.parse_arguments(["--mode", "normal"])
            problems = [
                Problem(ProblemType.CONFIG_INVALID, 5, f"Test problem {i}")
            ]
            manager.create_repair_plan(problems)
            
        # 强制垃圾回收
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # 内存增长应该在合理范围内
        growth = final_objects - initial_objects
        self.assertLess(growth, 1000)  # 允许少量增长


def run_performance_benchmark():
    """运行性能基准测试"""
    print("\n" + "="*60)
    print("🚀 性能基准测试")
    print("="*60)
    
    # 异常处理性能测试
    print("\n1. 异常处理性能测试...")
    center = ExceptionHandlingCenter()
    
    start_time = time.time()
    for i in range(10000):
        try:
            if i % 3 == 0:
                raise ValueError("Test")
            elif i % 5 == 0:
                raise TypeError("Test")
            else:
                raise RuntimeError("Test")
        except Exception as e:
            center.handle_exception(e)
    
    elapsed = time.time() - start_time
    print(f"   处理10000个异常用时: {elapsed:.2f}秒")
    print(f"   平均每秒处理: {10000/elapsed:.0f}个异常")
    
    # 智能启动性能测试
    print("\n2. 智能启动性能测试...")
    starter = IntelligentStarter()
    
    start_time = time.time()
    for i in range(100):
        config = starter.parse_arguments(["--mode", "diagnostic", "--verbose"])
    elapsed = time.time() - start_time
    print(f"   100次参数解析用时: {elapsed:.3f}秒")
    
    # 诊断工具性能测试
    print("\n3. 诊断工具性能测试...")
    runner = DiagnosticRunner()
    
    start_time = time.time()
    results = runner.run_all("json")
    elapsed = time.time() - start_time
    print(f"   完整诊断用时: {elapsed:.2f}秒")
    
    print("\n✅ 性能基准测试完成")


def main():
    """主测试入口"""
    print("=" * 60)
    print("🧪 Android系统修复工具闪退问题修复 - 综合测试")
    print("=" * 60)
    
    # 运行单元测试
    print("\n📋 运行单元测试...")
    
    # 创建测试套件
    test_suite = unittest.TestSuite()
    
    # 添加测试类
    test_classes = [
        TestExceptionHandlingCenter,
        TestIntelligentStarter,
        TestAutoRepairManager,
        TestDiagnosticTools,
        TestLoggerEnhancements,
        TestIntegrationScenarios,
        TestPerformanceAndStability
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # 显示测试结果
    print(f"\n📊 测试结果:")
    print(f"   运行测试: {result.testsRun}")
    print(f"   成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   失败: {len(result.failures)}")
    print(f"   错误: {len(result.errors)}")
    
    if result.failures:
        print(f"\n❌ 失败的测试:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split('AssertionError: ')[-1].strip()}")
    
    if result.errors:
        print(f"\n💥 错误的测试:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split('Exception: ')[-1].strip()}")
    
    # 运行性能基准测试
    if result.wasSuccessful():
        run_performance_benchmark()
    
    # 返回结果
    success = result.wasSuccessful()
    print(f"\n{'✅ 所有测试通过!' if success else '❌ 部分测试失败!'}")
    
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)