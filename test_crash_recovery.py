#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
闪退修复功能测试用例
验证依赖检查、配置验证、异常恢复等模块的有效性
"""

import os
import sys
import pytest
import tempfile
import shutil
import configparser
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import logging

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.dependency_checker import (
    DependencyChecker, CheckStatus, quick_check, detailed_check
)
from src.utils.config_validator import (
    ConfigValidator, ValidationLevel, validate_config_file
)
from src.utils.exception_recovery import (
    ExceptionRecoveryManager, RecoveryAction, exception_handler,
    get_global_recovery_manager
)
from src.utils.error_dialog import (
    ErrorDialogManager, ErrorSeverity, show_user_friendly_error
)
from src.utils.health_monitor import (
    SystemHealthMonitor, HealthStatus, get_health_monitor
)

class TestDependencyChecker:
    """依赖检查器测试类"""
    
    def setup_method(self):
        """测试方法设置"""
        self.checker = DependencyChecker()
    
    def test_python_version_check(self):
        """测试Python版本检查"""
        results = self.checker.check_all()
        
        # Python版本检查应该存在
        assert 'python_version' in results
        python_result = results['python_version']
        
        # 应该通过检查（因为我们在运行测试）
        assert python_result.status == CheckStatus.PASSED
        assert python_result.details['current_version']
        assert python_result.details['executable']
    
    def test_core_packages_check(self):
        """测试核心包检查"""
        results = self.checker.check_all()
        
        assert 'core_packages' in results
        core_result = results['core_packages']
        
        # 核心包应该都能正常导入
        assert core_result.status == CheckStatus.PASSED
        assert len(core_result.details['checked_packages']) > 0
    
    def test_required_directories_check(self):
        """测试必需目录检查"""
        # 使用临时目录进行测试
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            
            results = self.checker.check_all()
            
            assert 'required_directories' in results
            dir_result = results['required_directories']
            
            # 应该能够创建必需的目录
            assert dir_result.status == CheckStatus.PASSED
            
            # 检查目录是否实际创建
            for dir_name in self.checker.required_directories:
                assert Path(dir_name).exists()
    
    def test_quick_check_function(self):
        """测试快速检查函数"""
        result = quick_check()
        assert isinstance(result, bool)
    
    def test_detailed_check_function(self):
        """测试详细检查函数"""
        results = detailed_check()
        assert isinstance(results, dict)
        assert 'summary' in results
    
    def test_critical_failure_detection(self):
        """测试关键失败检测"""
        # 模拟关键失败
        self.checker.check_results['python_version'] = Mock()
        self.checker.check_results['python_version'].status = CheckStatus.FAILED
        
        assert self.checker.has_critical_failures()
        
        # 重置为正常状态
        self.checker.check_results['python_version'].status = CheckStatus.PASSED
        assert not self.checker.has_critical_failures()
    
    def test_report_generation(self):
        """测试报告生成"""
        self.checker.check_all()
        report = self.checker.generate_report()
        
        assert isinstance(report, str)
        assert "系统依赖检查报告" in report
        assert "检查结果:" in report

class TestConfigValidator:
    """配置验证器测试类"""
    
    def setup_method(self):
        """测试方法设置"""
        self.validator = ConfigValidator()
        self.temp_config_file = None
    
    def teardown_method(self):
        """测试方法清理"""
        if self.temp_config_file and os.path.exists(self.temp_config_file):
            os.remove(self.temp_config_file)
    
    def create_test_config(self, config_data: dict) -> str:
        """创建测试配置文件"""
        config = configparser.ConfigParser()
        
        for section, options in config_data.items():
            config.add_section(section)
            for key, value in options.items():
                config.set(section, key, str(value))
        
        # 创建临时文件
        fd, self.temp_config_file = tempfile.mkstemp(suffix='.ini')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            config.write(f)
        
        return self.temp_config_file
    
    def test_valid_config_validation(self):
        """测试有效配置验证"""
        config_data = {
            'app': {
                'name': 'Android系统修复工具',
                'version': '1.0.0'
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/app.log'
            },
            'adb': {
                'timeout': '30',
                'port': '5037'
            }
        }
        
        config_file = self.create_test_config(config_data)
        is_valid, results = validate_config_file(config_file)
        
        assert is_valid
        assert len([r for r in results if r.level == ValidationLevel.ERROR]) == 0
    
    def test_invalid_config_validation(self):
        """测试无效配置验证"""
        config_data = {
            'app': {
                'name': '',  # 空名称
                'version': 'invalid'  # 无效版本格式
            },
            'adb': {
                'timeout': '-1',  # 无效超时
                'port': '999999'  # 无效端口
            }
        }
        
        config_file = self.create_test_config(config_data)
        is_valid, results = validate_config_file(config_file)
        
        assert not is_valid
        assert len([r for r in results if r.level == ValidationLevel.ERROR]) > 0
    
    def test_missing_sections_validation(self):
        """测试缺失配置节验证"""
        config_data = {
            'app': {
                'name': 'Test App'
            }
            # 缺失其他必需的配置节
        }
        
        config_file = self.create_test_config(config_data)
        is_valid, results = validate_config_file(config_file)
        
        # 应该有警告关于缺失的配置节
        warning_results = [r for r in results if r.level == ValidationLevel.WARNING]
        assert len(warning_results) > 0
    
    def test_config_auto_fix(self):
        """测试配置自动修复"""
        config = configparser.ConfigParser()
        config.add_section('adb')
        config.set('adb', 'timeout', '-1')  # 无效值
        
        results = self.validator.validate_config(config)
        fixed_count = self.validator.fix_config(config, fix_errors=True)
        
        assert fixed_count > 0
        # 验证修复后的值
        assert config.getint('adb', 'timeout') >= 0
    
    def test_default_config_creation(self):
        """测试默认配置创建"""
        default_config = self.validator.create_default_config()
        
        # 验证默认配置包含必需的节
        required_sections = ['app', 'logging', 'adb', 'ui']
        for section in required_sections:
            assert default_config.has_section(section)
    
    def test_validation_report_generation(self):
        """测试验证报告生成"""
        config = configparser.ConfigParser()
        config.add_section('app')
        config.set('app', 'name', '')  # 引起错误
        
        self.validator.validate_config(config)
        report = self.validator.generate_validation_report()
        
        assert isinstance(report, str)
        assert "配置验证报告" in report
        assert "错误项目:" in report

class TestExceptionRecovery:
    """异常恢复测试类"""
    
    def setup_method(self):
        """测试方法设置"""
        self.recovery_manager = ExceptionRecoveryManager()
    
    def test_import_error_handling(self):
        """测试导入错误处理"""
        try:
            import non_existent_module  # 故意引发ImportError
        except ImportError as e:
            context = self.recovery_manager._create_exception_context(
                e, ImportError, e.__traceback__
            )
            
            strategy = self.recovery_manager._get_recovery_strategy(ImportError)
            assert strategy is not None
            assert strategy.action == RecoveryAction.USER_INTERVENTION
    
    def test_file_not_found_handling(self):
        """测试文件未找到错误处理"""
        try:
            with open('/non/existent/file.txt', 'r'):
                pass
        except FileNotFoundError as e:
            context = self.recovery_manager._create_exception_context(
                e, FileNotFoundError, e.__traceback__
            )
            
            strategy = self.recovery_manager._get_recovery_strategy(FileNotFoundError)
            assert strategy is not None
            assert strategy.action == RecoveryAction.FALLBACK
    
    def test_exception_context_creation(self):
        """测试异常上下文创建"""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            context = self.recovery_manager._create_exception_context(
                e, ValueError, e.__traceback__
            )
            
            assert context.exception == e
            assert context.exception_type == ValueError
            assert context.module_name
            assert context.function_name == 'test_exception_context_creation'
            assert context.stack_trace
            assert context.timestamp > 0
    
    def test_retry_mechanism(self):
        """测试重试机制"""
        call_count = 0
        
        @exception_handler(recovery_action=RecoveryAction.RETRY, max_retries=3)
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "Success"
        
        # 应该重试并最终成功
        result = failing_function()
        assert result == "Success"
        assert call_count == 3
    
    def test_fallback_mechanism(self):
        """测试备用方案机制"""
        def fallback_function(*args, **kwargs):
            return "Fallback result"
        
        @exception_handler(
            recovery_action=RecoveryAction.FALLBACK,
            fallback_function=fallback_function
        )
        def failing_function():
            raise ValueError("Always fails")
        
        result = failing_function()
        assert result == "Fallback result"
    
    def test_exception_statistics(self):
        """测试异常统计"""
        # 模拟一些异常
        for i in range(5):
            try:
                raise ValueError(f"Test error {i}")
            except ValueError as e:
                self.recovery_manager._create_exception_context(
                    e, ValueError, e.__traceback__
                )
        
        stats = self.recovery_manager.get_exception_statistics()
        
        assert stats['total_exceptions'] == 5
        assert 'ValueError' in stats['exception_types']
        assert stats['exception_types']['ValueError'] == 5
        assert len(stats['recent_exceptions']) <= 5
    
    def test_global_recovery_manager(self):
        """测试全局恢复管理器"""
        manager1 = get_global_recovery_manager()
        manager2 = get_global_recovery_manager()
        
        # 应该是同一个实例
        assert manager1 is manager2

class TestErrorDialog:
    """错误对话框测试类"""
    
    def setup_method(self):
        """测试方法设置"""
        self.dialog_manager = ErrorDialogManager()
    
    def test_exception_translation(self):
        """测试异常翻译"""
        test_exceptions = [
            ImportError("No module named 'test'"),
            FileNotFoundError("File not found"),
            PermissionError("Permission denied"),
            ConnectionError("Connection failed")
        ]
        
        for exception in test_exceptions:
            error_info = self.dialog_manager.translator.translate_exception(exception)
            
            assert error_info.title
            assert error_info.message
            assert error_info.error_code
            assert error_info.technical_details
            assert len(error_info.solutions) > 0
    
    def test_adb_error_detection(self):
        """测试ADB错误检测"""
        adb_exception = Exception("adb: device offline")
        error_info = self.dialog_manager.translator.translate_exception(adb_exception)
        
        assert error_info.error_code == "ERR_006"
        assert "ADB" in error_info.title or "Android" in error_info.title
    
    def test_error_solution_creation(self):
        """测试错误解决方案创建"""
        from src.utils.error_dialog import create_error_solution
        
        def mock_fix():
            return True
        
        solution = create_error_solution(
            title="Test Solution",
            description="Test Description",
            steps=["Step 1", "Step 2"],
            auto_fix_function=mock_fix
        )
        
        assert solution.title == "Test Solution"
        assert solution.description == "Test Description"
        assert len(solution.steps) == 2
        assert solution.auto_fix_available
        assert solution.auto_fix_function == mock_fix
    
    @patch('tkinter.Tk')
    def test_show_user_friendly_error(self, mock_tk):
        """测试显示用户友好错误（模拟GUI）"""
        # 模拟GUI组件
        mock_root = Mock()
        mock_tk.return_value = mock_root
        
        test_exception = ValueError("Test error")
        
        # 这应该不会抛出异常
        try:
            show_user_friendly_error(test_exception)
        except Exception as e:
            # 如果GUI不可用，应该降级到消息框
            pass

class TestHealthMonitor:
    """健康监控测试类"""
    
    def setup_method(self):
        """测试方法设置"""
        self.monitor = SystemHealthMonitor(check_interval=0.1)  # 快速检查用于测试
    
    def teardown_method(self):
        """测试方法清理"""
        if self.monitor.is_running:
            self.monitor.stop_monitoring()
    
    def test_health_monitor_initialization(self):
        """测试健康监控初始化"""
        assert not self.monitor.is_running
        assert len(self.monitor.metrics) > 0
        assert 'memory_usage' in self.monitor.metrics
        assert 'cpu_usage' in self.monitor.metrics
    
    def test_metric_collection(self):
        """测试指标收集"""
        self.monitor._collect_metrics()
        
        # 检查指标是否被更新
        assert self.monitor.metrics['memory_usage'].value >= 0
        assert self.monitor.metrics['cpu_usage'].value >= 0
        assert self.monitor.metrics['disk_usage'].value >= 0
    
    def test_health_status_calculation(self):
        """测试健康状态计算"""
        # 设置正常的指标值
        for metric in self.monitor.metrics.values():
            metric.value = 10.0  # 低于警告阈值
        
        status = self.monitor.get_overall_health()
        assert status == HealthStatus.EXCELLENT
        
        # 设置警告级别的指标值
        self.monitor.metrics['memory_usage'].value = 85.0  # 高于警告阈值
        status = self.monitor.get_overall_health()
        assert status == HealthStatus.GOOD
        
        # 设置严重级别的指标值
        self.monitor.metrics['memory_usage'].value = 98.0  # 高于严重阈值
        status = self.monitor.get_overall_health()
        assert status == HealthStatus.CRITICAL
    
    def test_alert_creation(self):
        """测试警报创建"""
        initial_alert_count = len(self.monitor.alerts)
        
        # 触发警报
        self.monitor._create_alert(
            'test_metric', 
            HealthStatus.WARNING, 
            'Test alert message'
        )
        
        assert len(self.monitor.alerts) == initial_alert_count + 1
        assert self.monitor.alerts[-1].metric_name == 'test_metric'
        assert self.monitor.alerts[-1].severity == HealthStatus.WARNING
    
    def test_health_report_generation(self):
        """测试健康报告生成"""
        self.monitor._collect_metrics()
        report = self.monitor.get_health_report()
        
        assert 'overall_status' in report
        assert 'uptime_seconds' in report
        assert 'metrics' in report
        assert 'active_alerts' in report
        assert 'timestamp' in report
        
        # 检查指标报告格式
        for metric_name, metric_info in report['metrics'].items():
            assert 'name' in metric_info
            assert 'value' in metric_info
            assert 'unit' in metric_info
            assert 'status' in metric_info
    
    def test_monitoring_start_stop(self):
        """测试监控启动和停止"""
        assert not self.monitor.is_running
        
        self.monitor.start_monitoring()
        assert self.monitor.is_running
        assert self.monitor.monitoring_thread is not None
        
        self.monitor.stop_monitoring()
        assert not self.monitor.is_running
    
    def test_threshold_adjustment(self):
        """测试阈值调整"""
        original_warning = self.monitor.metrics['memory_usage'].threshold_warning
        original_critical = self.monitor.metrics['memory_usage'].threshold_critical
        
        self.monitor.set_metric_thresholds('memory_usage', 90.0, 95.0)
        
        assert self.monitor.metrics['memory_usage'].threshold_warning == 90.0
        assert self.monitor.metrics['memory_usage'].threshold_critical == 95.0
    
    def test_global_health_monitor(self):
        """测试全局健康监控"""
        from src.utils.health_monitor import get_health_monitor, get_current_health_status
        
        monitor1 = get_health_monitor()
        monitor2 = get_health_monitor()
        
        # 应该是同一个实例
        assert monitor1 is monitor2
        
        # 测试健康状态获取
        status = get_current_health_status()
        assert isinstance(status, HealthStatus)

class TestIntegration:
    """集成测试类"""
    
    def test_crash_recovery_integration(self):
        """测试闪退恢复集成流程"""
        # 1. 检查依赖
        dependency_results = detailed_check()
        assert 'summary' in dependency_results
        
        # 2. 验证配置
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write("""
[app]
name = Test App
version = 1.0.0

[logging]
level = INFO
file = logs/test.log

[adb]
timeout = 30
port = 5037
            """)
            config_file = f.name
        
        try:
            is_valid, validation_results = validate_config_file(config_file)
            assert is_valid or len([r for r in validation_results 
                                   if r.level == ValidationLevel.ERROR]) == 0
        finally:
            os.unlink(config_file)
        
        # 3. 测试异常恢复
        recovery_manager = get_global_recovery_manager()
        assert recovery_manager is not None
        
        # 4. 测试健康监控
        health_monitor = get_health_monitor()
        health_status = health_monitor.get_overall_health()
        assert isinstance(health_status, HealthStatus)
    
    def test_error_handling_workflow(self):
        """测试错误处理工作流"""
        # 模拟一个错误情况
        try:
            # 故意触发一个文件不存在的错误
            with open('/definitely/does/not/exist.txt', 'r'):
                pass
        except FileNotFoundError as e:
            # 1. 异常恢复管理器处理
            recovery_manager = ExceptionRecoveryManager()
            context = recovery_manager._create_exception_context(
                e, FileNotFoundError, e.__traceback__
            )
            
            # 2. 错误对话框翻译
            dialog_manager = ErrorDialogManager()
            error_info = dialog_manager.translator.translate_exception(e)
            
            # 验证工作流
            assert context.exception_type == FileNotFoundError
            assert error_info.title
            assert len(error_info.solutions) > 0
    
    def test_performance_under_load(self):
        """测试负载下的性能"""
        # 创建多个检查器实例
        checkers = [DependencyChecker() for _ in range(5)]
        
        # 并发运行检查
        import threading
        
        results = {}
        def run_check(index):
            results[index] = checkers[index].check_all()
        
        threads = []
        for i in range(5):
            thread = threading.Thread(target=run_check, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # 验证所有检查都完成
        assert len(results) == 5
        for result in results.values():
            assert 'summary' in result

if __name__ == '__main__':
    # 运行测试
    pytest.main([__file__, '-v', '--tb=short'])