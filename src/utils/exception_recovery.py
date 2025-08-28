#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异常捕获与恢复框架
用于处理各种运行时异常，防止应用闪退，提供恢复机制
"""

import sys
import os
import traceback
import logging
import time
import threading
from typing import Dict, List, Any, Callable, Optional, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import configparser

class RecoveryAction(Enum):
    """恢复动作枚举"""
    IGNORE = "ignore"                   # 忽略异常
    RETRY = "retry"                     # 重试操作
    FALLBACK = "fallback"               # 使用备用方案
    RESET_COMPONENT = "reset_component" # 重置组件
    RELOAD_CONFIG = "reload_config"     # 重新加载配置
    RESTART_SERVICE = "restart_service" # 重启服务
    SAFE_EXIT = "safe_exit"            # 安全退出
    USER_INTERVENTION = "user_intervention" # 需要用户干预

@dataclass
class ExceptionContext:
    """异常上下文信息"""
    exception: Exception
    exception_type: Type[Exception]
    module_name: str
    function_name: str
    line_number: int
    timestamp: float
    stack_trace: str
    additional_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RecoveryStrategy:
    """恢复策略"""
    action: RecoveryAction
    max_retries: int = 3
    retry_delay: float = 1.0
    fallback_function: Optional[Callable] = None
    recovery_function: Optional[Callable] = None
    user_message: str = ""
    log_level: int = logging.ERROR

class ExceptionRecoveryManager:
    """异常恢复管理器"""
    
    def __init__(self):
        """初始化异常恢复管理器"""
        self.logger = logging.getLogger(__name__)
        self.recovery_strategies: Dict[Type[Exception], RecoveryStrategy] = {}
        self.exception_history: List[ExceptionContext] = []
        self.retry_counts: Dict[str, int] = {}
        self.component_states: Dict[str, Any] = {}
        
        # 安装全局异常处理器
        self._install_global_handlers()
        
        # 定义默认恢复策略
        self._define_default_strategies()
    
    def _install_global_handlers(self):
        """安装全局异常处理器"""
        # 设置全局异常处理器
        sys.excepthook = self._global_exception_handler
        
        # 设置线程异常处理器
        threading.excepthook = self._thread_exception_handler
    
    def _global_exception_handler(self, exc_type, exc_value, exc_traceback):
        """全局异常处理器"""
        if exc_type == KeyboardInterrupt:
            # 用户中断，正常退出
            self.logger.info("用户中断程序")
            sys.exit(0)
        
        # 记录异常
        context = self._create_exception_context(
            exc_value, exc_type, exc_traceback
        )
        
        self.logger.critical(f"未捕获的异常: {context.exception}")
        self.logger.critical(f"异常堆栈:\n{context.stack_trace}")
        
        # 尝试恢复
        recovery_success = self._handle_exception(context)
        
        if not recovery_success:
            # 无法恢复，安全退出
            self.logger.critical("无法恢复，程序将安全退出")
            self._safe_exit(1)
    
    def _thread_exception_handler(self, args):
        """线程异常处理器"""
        exc_type = args.exc_type
        exc_value = args.exc_value
        exc_traceback = args.exc_traceback
        thread = args.thread
        
        # 记录线程异常
        context = self._create_exception_context(
            exc_value, exc_type, exc_traceback
        )
        context.additional_info['thread_name'] = thread.name
        
        self.logger.error(f"线程 {thread.name} 发生异常: {context.exception}")
        
        # 尝试恢复
        self._handle_exception(context)
    
    def _define_default_strategies(self):
        """定义默认恢复策略"""
        # 导入错误 - 通常是致命的
        self.recovery_strategies[ImportError] = RecoveryStrategy(
            action=RecoveryAction.USER_INTERVENTION,
            user_message="缺少必要的依赖包，请安装相关依赖",
            log_level=logging.CRITICAL
        )
        
        # 配置错误 - 可以尝试重建配置
        self.recovery_strategies[configparser.Error] = RecoveryStrategy(
            action=RecoveryAction.RELOAD_CONFIG,
            max_retries=1,
            user_message="配置文件有误，将尝试重建默认配置",
            log_level=logging.ERROR
        )
        
        # 文件/目录错误 - 可以尝试创建或使用备用路径
        self.recovery_strategies[FileNotFoundError] = RecoveryStrategy(
            action=RecoveryAction.FALLBACK,
            max_retries=2,
            user_message="文件或目录不存在，将尝试创建或使用默认路径",
            log_level=logging.WARNING
        )
        
        self.recovery_strategies[PermissionError] = RecoveryStrategy(
            action=RecoveryAction.FALLBACK,
            max_retries=1,
            user_message="权限不足，将尝试使用备用方案",
            log_level=logging.WARNING
        )
        
        # 网络错误 - 可以重试
        self.recovery_strategies[ConnectionError] = RecoveryStrategy(
            action=RecoveryAction.RETRY,
            max_retries=3,
            retry_delay=2.0,
            user_message="网络连接失败，将自动重试",
            log_level=logging.WARNING
        )
        
        # 内存错误 - 尝试清理资源
        self.recovery_strategies[MemoryError] = RecoveryStrategy(
            action=RecoveryAction.RESET_COMPONENT,
            max_retries=1,
            user_message="内存不足，将清理资源后重试",
            log_level=logging.ERROR
        )
        
        # 值错误 - 使用默认值
        self.recovery_strategies[ValueError] = RecoveryStrategy(
            action=RecoveryAction.FALLBACK,
            max_retries=1,
            user_message="数据格式错误，将使用默认值",
            log_level=logging.WARNING
        )
        
        # 超时错误 - 重试
        self.recovery_strategies[TimeoutError] = RecoveryStrategy(
            action=RecoveryAction.RETRY,
            max_retries=2,
            retry_delay=5.0,
            user_message="操作超时，将延长超时时间后重试",
            log_level=logging.WARNING
        )
        
        # OSError - 根据具体错误码决定策略
        self.recovery_strategies[OSError] = RecoveryStrategy(
            action=RecoveryAction.FALLBACK,
            max_retries=2,
            user_message="系统错误，将尝试备用方案",
            log_level=logging.ERROR
        )
    
    def _create_exception_context(self, exception: Exception, 
                                 exc_type: Type[Exception], 
                                 exc_traceback) -> ExceptionContext:
        """创建异常上下文"""
        # 获取异常发生的位置信息
        tb_frame = exc_traceback.tb_frame if exc_traceback else None
        module_name = tb_frame.f_globals.get('__name__', 'unknown') if tb_frame else 'unknown'
        function_name = tb_frame.f_code.co_name if tb_frame else 'unknown'
        line_number = exc_traceback.tb_lineno if exc_traceback else 0
        
        # 生成堆栈跟踪
        stack_trace = ''.join(traceback.format_exception(exc_type, exception, exc_traceback))
        
        context = ExceptionContext(
            exception=exception,
            exception_type=exc_type,
            module_name=module_name,
            function_name=function_name,
            line_number=line_number,
            timestamp=time.time(),
            stack_trace=stack_trace
        )
        
        # 保存到历史记录
        self.exception_history.append(context)
        
        # 保持历史记录在合理大小
        if len(self.exception_history) > 100:
            self.exception_history = self.exception_history[-50:]
        
        return context
    
    def _handle_exception(self, context: ExceptionContext) -> bool:
        """
        处理异常
        
        Args:
            context: 异常上下文
            
        Returns:
            是否成功恢复
        """
        strategy = self._get_recovery_strategy(context.exception_type)
        
        if not strategy:
            self.logger.error(f"未找到 {context.exception_type.__name__} 的恢复策略")
            return False
        
        # 记录异常处理开始
        self.logger.log(
            strategy.log_level,
            f"开始处理异常: {context.exception} (策略: {strategy.action.value})"
        )
        
        try:
            if strategy.action == RecoveryAction.IGNORE:
                return self._ignore_exception(context, strategy)
            elif strategy.action == RecoveryAction.RETRY:
                return self._retry_operation(context, strategy)
            elif strategy.action == RecoveryAction.FALLBACK:
                return self._use_fallback(context, strategy)
            elif strategy.action == RecoveryAction.RESET_COMPONENT:
                return self._reset_component(context, strategy)
            elif strategy.action == RecoveryAction.RELOAD_CONFIG:
                return self._reload_config(context, strategy)
            elif strategy.action == RecoveryAction.RESTART_SERVICE:
                return self._restart_service(context, strategy)
            elif strategy.action == RecoveryAction.SAFE_EXIT:
                return self._safe_exit(0)
            elif strategy.action == RecoveryAction.USER_INTERVENTION:
                return self._request_user_intervention(context, strategy)
            else:
                self.logger.error(f"未知的恢复动作: {strategy.action}")
                return False
                
        except Exception as recovery_exception:
            self.logger.error(f"恢复策略执行失败: {recovery_exception}")
            return False
    
    def _get_recovery_strategy(self, exc_type: Type[Exception]) -> Optional[RecoveryStrategy]:
        """获取恢复策略"""
        # 直接匹配
        if exc_type in self.recovery_strategies:
            return self.recovery_strategies[exc_type]
        
        # 查找父类匹配
        for strategy_type, strategy in self.recovery_strategies.items():
            if issubclass(exc_type, strategy_type):
                return strategy
        
        # 返回默认策略
        return RecoveryStrategy(
            action=RecoveryAction.USER_INTERVENTION,
            user_message="发生未知错误，需要人工处理",
            log_level=logging.ERROR
        )
    
    def _ignore_exception(self, context: ExceptionContext, 
                         strategy: RecoveryStrategy) -> bool:
        """忽略异常"""
        self.logger.info(f"忽略异常: {context.exception}")
        return True
    
    def _retry_operation(self, context: ExceptionContext,
                        strategy: RecoveryStrategy) -> bool:
        """重试操作"""
        retry_key = f"{context.module_name}.{context.function_name}"
        current_retries = self.retry_counts.get(retry_key, 0)
        
        if current_retries >= strategy.max_retries:
            self.logger.error(f"重试次数已达上限 {strategy.max_retries}")
            self.retry_counts[retry_key] = 0  # 重置计数
            return False
        
        self.retry_counts[retry_key] = current_retries + 1
        
        self.logger.info(f"重试操作 (第 {current_retries + 1}/{strategy.max_retries} 次)")
        
        # 等待重试延迟
        if strategy.retry_delay > 0:
            time.sleep(strategy.retry_delay)
        
        # 如果有自定义重试函数，调用它
        if strategy.recovery_function:
            try:
                return strategy.recovery_function(context)
            except Exception as e:
                self.logger.error(f"自定义重试函数失败: {e}")
                return False
        
        return True
    
    def _use_fallback(self, context: ExceptionContext,
                     strategy: RecoveryStrategy) -> bool:
        """使用备用方案"""
        self.logger.info(f"使用备用方案处理: {context.exception}")
        
        if strategy.fallback_function:
            try:
                return strategy.fallback_function(context)
            except Exception as e:
                self.logger.error(f"备用方案执行失败: {e}")
                return False
        
        # 默认备用处理
        if isinstance(context.exception, FileNotFoundError):
            return self._handle_file_not_found(context)
        elif isinstance(context.exception, PermissionError):
            return self._handle_permission_error(context)
        elif isinstance(context.exception, ValueError):
            return self._handle_value_error(context)
        
        return False
    
    def _reset_component(self, context: ExceptionContext,
                        strategy: RecoveryStrategy) -> bool:
        """重置组件"""
        self.logger.info(f"重置组件: {context.module_name}")
        
        # 如果有自定义重置函数，调用它
        if strategy.recovery_function:
            try:
                return strategy.recovery_function(context)
            except Exception as e:
                self.logger.error(f"组件重置失败: {e}")
                return False
        
        # 默认重置处理
        component_key = context.module_name
        if component_key in self.component_states:
            # 恢复到初始状态
            del self.component_states[component_key]
        
        # 触发垃圾回收
        import gc
        gc.collect()
        
        return True
    
    def _reload_config(self, context: ExceptionContext,
                      strategy: RecoveryStrategy) -> bool:
        """重新加载配置"""
        self.logger.info("重新加载配置")
        
        try:
            # 尝试重新创建默认配置
            from ..utils.config_validator import ConfigValidator
            
            validator = ConfigValidator()
            default_config = validator.create_default_config()
            
            # 保存默认配置
            config_file = 'config.ini'
            with open(config_file, 'w', encoding='utf-8') as f:
                default_config.write(f)
            
            self.logger.info("已重建默认配置文件")
            return True
            
        except Exception as e:
            self.logger.error(f"重新加载配置失败: {e}")
            return False
    
    def _restart_service(self, context: ExceptionContext,
                        strategy: RecoveryStrategy) -> bool:
        """重启服务"""
        self.logger.info(f"重启服务: {context.module_name}")
        
        if strategy.recovery_function:
            try:
                return strategy.recovery_function(context)
            except Exception as e:
                self.logger.error(f"服务重启失败: {e}")
                return False
        
        return False
    
    def _safe_exit(self, exit_code: int = 0) -> bool:
        """安全退出"""
        self.logger.info(f"执行安全退出 (退出码: {exit_code})")
        
        try:
            # 保存必要的状态
            self._save_crash_report()
            
            # 清理资源
            self._cleanup_resources()
            
            sys.exit(exit_code)
            
        except Exception as e:
            self.logger.error(f"安全退出失败: {e}")
            # 强制退出
            os._exit(exit_code)
    
    def _request_user_intervention(self, context: ExceptionContext,
                                  strategy: RecoveryStrategy) -> bool:
        """请求用户干预"""
        self.logger.error(f"需要用户干预: {strategy.user_message}")
        
        # 在GUI环境中显示错误对话框
        try:
            import tkinter as tk
            from tkinter import messagebox
            
            root = tk.Tk()
            root.withdraw()  # 隐藏主窗口
            
            messagebox.showerror(
                "错误", 
                f"{strategy.user_message}\n\n错误详情: {context.exception}"
            )
            
            root.destroy()
            
        except Exception:
            # 如果GUI不可用，输出到控制台
            print(f"\n*** 错误 ***")
            print(f"{strategy.user_message}")
            print(f"错误详情: {context.exception}")
            print("请检查日志文件获取更多信息")
        
        return False
    
    def _handle_file_not_found(self, context: ExceptionContext) -> bool:
        """处理文件未找到错误"""
        # 尝试创建缺失的目录或文件
        try:
            if hasattr(context.exception, 'filename') and context.exception.filename:
                file_path = context.exception.filename
                
                # 如果是目录，创建目录
                if '.' not in os.path.basename(file_path):
                    os.makedirs(file_path, exist_ok=True)
                    self.logger.info(f"已创建目录: {file_path}")
                    return True
                else:
                    # 如果是文件，创建父目录
                    parent_dir = os.path.dirname(file_path)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                        self.logger.info(f"已创建父目录: {parent_dir}")
                    return True
            
        except Exception as e:
            self.logger.error(f"创建文件/目录失败: {e}")
        
        return False
    
    def _handle_permission_error(self, context: ExceptionContext) -> bool:
        """处理权限错误"""
        self.logger.warning("检测到权限问题，建议以管理员权限运行程序")
        
        # 尝试使用临时目录
        try:
            import tempfile
            
            temp_dir = tempfile.gettempdir()
            self.logger.info(f"使用临时目录: {temp_dir}")
            
            # 可以在这里设置使用临时目录的逻辑
            return True
            
        except Exception as e:
            self.logger.error(f"使用临时目录失败: {e}")
        
        return False
    
    def _handle_value_error(self, context: ExceptionContext) -> bool:
        """处理值错误"""
        self.logger.warning("检测到数据格式错误，将使用默认值")
        # 这里可以实现具体的默认值逻辑
        return True
    
    def _save_crash_report(self):
        """保存崩溃报告"""
        try:
            crash_report_path = "logs/crash_report.txt"
            os.makedirs(os.path.dirname(crash_report_path), exist_ok=True)
            
            with open(crash_report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("崩溃报告\n")
                f.write("=" * 60 + "\n")
                f.write(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Python版本: {sys.version}\n")
                f.write(f"异常历史记录:\n\n")
                
                for context in self.exception_history[-10:]:  # 最近10个异常
                    f.write(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(context.timestamp))}\n")
                    f.write(f"模块: {context.module_name}\n")
                    f.write(f"函数: {context.function_name}\n")
                    f.write(f"行号: {context.line_number}\n")
                    f.write(f"异常: {context.exception}\n")
                    f.write(f"堆栈:\n{context.stack_trace}\n")
                    f.write("-" * 40 + "\n")
            
            self.logger.info(f"崩溃报告已保存: {crash_report_path}")
            
        except Exception as e:
            self.logger.error(f"保存崩溃报告失败: {e}")
    
    def _cleanup_resources(self):
        """清理资源"""
        try:
            # 关闭日志处理器
            for handler in logging.getLogger().handlers[:]:
                handler.close()
                logging.getLogger().removeHandler(handler)
            
            # 其他清理逻辑
            self.logger.info("资源清理完成")
            
        except Exception as e:
            print(f"资源清理失败: {e}")
    
    def add_recovery_strategy(self, exc_type: Type[Exception], 
                             strategy: RecoveryStrategy):
        """添加自定义恢复策略"""
        self.recovery_strategies[exc_type] = strategy
        self.logger.info(f"已添加 {exc_type.__name__} 的恢复策略")
    
    def get_exception_statistics(self) -> Dict[str, Any]:
        """获取异常统计信息"""
        stats = {
            'total_exceptions': len(self.exception_history),
            'exception_types': {},
            'modules_with_exceptions': {},
            'recent_exceptions': []
        }
        
        for context in self.exception_history:
            # 统计异常类型
            exc_type_name = context.exception_type.__name__
            stats['exception_types'][exc_type_name] = stats['exception_types'].get(exc_type_name, 0) + 1
            
            # 统计异常模块
            module_name = context.module_name
            stats['modules_with_exceptions'][module_name] = stats['modules_with_exceptions'].get(module_name, 0) + 1
        
        # 最近的异常
        stats['recent_exceptions'] = [
            {
                'timestamp': context.timestamp,
                'exception_type': context.exception_type.__name__,
                'module': context.module_name,
                'message': str(context.exception)
            }
            for context in self.exception_history[-5:]  # 最近5个
        ]
        
        return stats

# 装饰器函数
def exception_handler(recovery_action: RecoveryAction = RecoveryAction.FALLBACK,
                     max_retries: int = 3,
                     retry_delay: float = 1.0,
                     fallback_function: Optional[Callable] = None,
                     user_message: str = ""):
    """
    异常处理装饰器
    
    Args:
        recovery_action: 恢复动作
        max_retries: 最大重试次数
        retry_delay: 重试延迟
        fallback_function: 备用函数
        user_message: 用户消息
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # 获取全局恢复管理器实例
                manager = getattr(wrapper, '_recovery_manager', None)
                if not manager:
                    manager = ExceptionRecoveryManager()
                    wrapper._recovery_manager = manager
                
                # 创建自定义策略
                strategy = RecoveryStrategy(
                    action=recovery_action,
                    max_retries=max_retries,
                    retry_delay=retry_delay,
                    fallback_function=fallback_function,
                    user_message=user_message or f"函数 {func.__name__} 执行失败"
                )
                
                # 创建异常上下文
                context = manager._create_exception_context(e, type(e), e.__traceback__)
                
                # 处理异常
                success = manager._handle_exception(context)
                
                if not success and fallback_function:
                    return fallback_function(*args, **kwargs)
                
                # 如果是重试策略且成功，重新调用原函数
                if success and recovery_action == RecoveryAction.RETRY:
                    return func(*args, **kwargs)
                
                # 其他情况返回None或抛出异常
                if not success:
                    raise e
                
                return None
        
        return wrapper
    return decorator

# 全局恢复管理器实例
_global_recovery_manager = None

def get_global_recovery_manager() -> ExceptionRecoveryManager:
    """获取全局恢复管理器实例"""
    global _global_recovery_manager
    if _global_recovery_manager is None:
        _global_recovery_manager = ExceptionRecoveryManager()
    return _global_recovery_manager

__all__ = [
    'ExceptionRecoveryManager', 'RecoveryAction', 'RecoveryStrategy', 
    'ExceptionContext', 'exception_handler', 'get_global_recovery_manager'
]