"""
异常处理中心
提供全方位的异常处理策略和恢复机制
"""

import sys
import traceback
import threading
import time
from typing import Dict, List, Any, Callable, Optional, Type, Union
from enum import Enum
from dataclasses import dataclass
from functools import wraps
import logging

from .logger import setup_logger


class ExceptionSeverity(Enum):
    """异常严重程度"""
    LOW = "low"           # 轻微异常，程序可继续运行
    MEDIUM = "medium"     # 中等异常，需要处理但不影响核心功能
    HIGH = "high"         # 严重异常，可能影响核心功能
    CRITICAL = "critical" # 严重异常，需要立即处理或退出


class RecoveryAction(Enum):
    """恢复动作类型"""
    RETRY = "retry"              # 重试操作
    FALLBACK = "fallback"        # 使用备用方案
    RESTART_MODULE = "restart"   # 重启模块
    SAFE_EXIT = "safe_exit"      # 安全退出
    USER_INTERVENTION = "user"   # 需要用户干预


@dataclass
class ExceptionContext:
    """异常上下文信息"""
    module_name: str
    function_name: str
    timestamp: float
    thread_id: int
    additional_info: Dict[str, Any]


@dataclass
class RecoveryStrategy:
    """恢复策略"""
    action: RecoveryAction
    max_retries: int = 3
    retry_delay: float = 1.0
    fallback_handler: Optional[Callable] = None
    user_message: str = ""
    auto_execute: bool = True


class ExceptionHandlingCenter:
    """异常处理中心"""
    
    def __init__(self):
        self.logger = setup_logger("ExceptionHandler")
        self._handlers: Dict[Type[Exception], Callable] = {}
        self._recovery_strategies: Dict[Type[Exception], RecoveryStrategy] = {}
        self._fallback_actions: Dict[str, Callable] = {}
        self._exception_history: List[Dict] = []
        self._lock = threading.RLock()
        
        # 注册默认异常处理器
        self._register_default_handlers()
    
    def register_handler(self, exception_type: Type[Exception], 
                        handler: Callable, 
                        strategy: RecoveryStrategy = None):  # pyright: ignore[reportArgumentType]
        """
        注册异常处理器
        
        Args:
            exception_type: 异常类型
            handler: 处理函数
            strategy: 恢复策略
        """
        with self._lock:
            self._handlers[exception_type] = handler
            if strategy:
                self._recovery_strategies[exception_type] = strategy
            
        self.logger.info(f"注册异常处理器: {exception_type.__name__}")
    
    def register_fallback_action(self, action_name: str, action_func: Callable):
        """注册备用动作"""
        with self._lock:
            self._fallback_actions[action_name] = action_func
        self.logger.info(f"注册备用动作: {action_name}")
    
    def handle_exception(self, exception: Exception, 
                        context: ExceptionContext = None,  # pyright: ignore[reportArgumentType]
                        severity: ExceptionSeverity = ExceptionSeverity.MEDIUM) -> bool:
        """
        处理异常
        
        Args:
            exception: 异常对象
            context: 异常上下文
            severity: 严重程度
            
        Returns:
            是否成功处理异常
        """
        try:
            with self._lock:
                # 记录异常信息
                self._record_exception(exception, context, severity)
                
                # 查找对应的处理器
                handler = self._find_handler(type(exception))
                if handler:
                    return self._execute_handler(handler, exception, context)
                
                # 使用默认处理策略
                return self._handle_default_exception(exception, context, severity)
                
        except Exception as e:
            self.logger.critical(f"异常处理器本身发生异常: {e}")
            return False
    
    def execute_recovery(self, strategy_name: str, **kwargs) -> bool:
        """
        执行恢复策略
        
        Args:
            strategy_name: 策略名称
            **kwargs: 策略参数
            
        Returns:
            恢复是否成功
        """
        try:
            if strategy_name in self._fallback_actions:
                action_func = self._fallback_actions[strategy_name]
                result = action_func(**kwargs)
                self.logger.info(f"执行恢复策略 {strategy_name} 成功")
                return result
            else:
                self.logger.error(f"未找到恢复策略: {strategy_name}")
                return False
        except Exception as e:
            self.logger.error(f"执行恢复策略失败: {e}")
            return False
    
    def get_exception_statistics(self) -> Dict[str, Any]:
        """获取异常统计信息"""
        with self._lock:
            total_exceptions = len(self._exception_history)
            if total_exceptions == 0:
                return {"total": 0}
            
            # 统计异常类型
            type_counts = {}
            severity_counts = {}
            
            for record in self._exception_history:
                exc_type = record.get("type", "Unknown")
                severity = record.get("severity", "unknown")
                
                type_counts[exc_type] = type_counts.get(exc_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            return {
                "total": total_exceptions,
                "by_type": type_counts,
                "by_severity": severity_counts,
                "recent": self._exception_history[-10:]  # 最近10条
            }
    
    def clear_exception_history(self):
        """清除异常历史记录"""
        with self._lock:
            self._exception_history.clear()
        self.logger.info("异常历史记录已清除")
    
    def _register_default_handlers(self):
        """注册默认异常处理器"""
        
        # 导入错误处理
        def handle_import_error(exc: ImportError, context: ExceptionContext = None):  # pyright: ignore[reportArgumentType]
            missing_module = str(exc).split("'")[1] if "'" in str(exc) else "unknown"
            self.logger.error(f"缺少依赖模块: {missing_module}")
            
            # 尝试自动安装
            try:
                import subprocess
                result = subprocess.run([sys.executable, "-m", "pip", "install", missing_module], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self.logger.info(f"成功安装模块: {missing_module}")
                    return True
            except Exception as e:
                self.logger.error(f"自动安装失败: {e}")
            
            return False
        
        # 文件操作错误处理
        def handle_file_error(exc: Union[FileNotFoundError, PermissionError], 
                            context: ExceptionContext = None):  # pyright: ignore[reportArgumentType]  # pyright: ignore[reportArgumentType]
            if isinstance(exc, FileNotFoundError):
                self.logger.error(f"文件未找到: {exc.filename}")
            elif isinstance(exc, PermissionError):
                self.logger.error(f"权限不足: {exc.filename}")
            
            # 提供用户指导
            return False
        
        # 网络错误处理
        def handle_network_error(exc: Exception, context: ExceptionContext = None):  # pyright: ignore[reportArgumentType]
            self.logger.error(f"网络连接错误: {exc}")
            # 可以实现重试逻辑
            return False
        
        # 注册处理器
        self.register_handler(ImportError, handle_import_error)
        self.register_handler(FileNotFoundError, handle_file_error)
        self.register_handler(PermissionError, handle_file_error)
        
        try:
            import requests
            self.register_handler(requests.exceptions.RequestException, handle_network_error)
        except ImportError:
            pass  # requests未安装时跳过
    
    def _find_handler(self, exception_type: Type[Exception]) -> Optional[Callable]:
        """查找异常处理器"""
        # 精确匹配
        if exception_type in self._handlers:
            return self._handlers[exception_type]
        
        # 查找父类匹配
        for registered_type, handler in self._handlers.items():
            if issubclass(exception_type, registered_type):
                return handler
        
        return None
    
    def _execute_handler(self, handler: Callable, exception: Exception, 
                        context: ExceptionContext = None) -> bool:  # pyright: ignore[reportArgumentType]
        """执行异常处理器"""
        try:
            if context:
                return handler(exception, context)
            else:
                return handler(exception)
        except Exception as e:
            self.logger.error(f"异常处理器执行失败: {e}")
            return False
    
    def _handle_default_exception(self, exception: Exception, 
                                 context: ExceptionContext = None,  # pyright: ignore[reportArgumentType]
                                 severity: ExceptionSeverity = ExceptionSeverity.MEDIUM) -> bool:
        """处理未注册的异常"""
        self.logger.error(f"未处理的异常 ({severity.value}): {type(exception).__name__}: {exception}")
        
        if severity == ExceptionSeverity.CRITICAL:
            self.logger.critical("严重异常，程序将退出")
            return False
        
        return True
    
    def _record_exception(self, exception: Exception, 
                         context: ExceptionContext = None,  # pyright: ignore[reportArgumentType]
                         severity: ExceptionSeverity = ExceptionSeverity.MEDIUM):
        """记录异常信息"""
        record = {
            "timestamp": time.time(),
            "type": type(exception).__name__,
            "message": str(exception),
            "severity": severity.value,
            "traceback": traceback.format_exc()
        }
        
        if context:
            record.update({
                "module": context.module_name,
                "function": context.function_name,
                "thread_id": context.thread_id,
                "additional_info": context.additional_info
            })
        
        self._exception_history.append(record)
        
        # 限制历史记录数量
        if len(self._exception_history) > 1000:
            self._exception_history = self._exception_history[-500:]


# 全局异常处理中心实例
_global_exception_center = None
_center_lock = threading.Lock()


def get_exception_center() -> ExceptionHandlingCenter:
    """获取全局异常处理中心实例"""
    global _global_exception_center
    if _global_exception_center is None:
        with _center_lock:
            if _global_exception_center is None:
                _global_exception_center = ExceptionHandlingCenter()
    return _global_exception_center


def exception_handler(severity: ExceptionSeverity = ExceptionSeverity.MEDIUM,
                     auto_recover: bool = True):
    """
    异常处理装饰器
    
    Args:
        severity: 异常严重程度
        auto_recover: 是否自动恢复
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = ExceptionContext(
                    module_name=func.__module__,
                    function_name=func.__name__,
                    timestamp=time.time(),
                    thread_id=threading.get_ident(),
                    additional_info={"args": str(args), "kwargs": str(kwargs)}
                )
                
                center = get_exception_center()
                handled = center.handle_exception(e, context, severity)
                
                if not handled and severity == ExceptionSeverity.CRITICAL:
                    raise e
                
                return None
        return wrapper
    return decorator


def safe_execute(func: Callable, *args, 
                default_return=None, 
                log_errors: bool = True,
                **kwargs) -> Any:
    """
    安全执行函数
    
    Args:
        func: 要执行的函数
        *args: 函数参数
        default_return: 异常时的默认返回值
        log_errors: 是否记录错误
        **kwargs: 函数关键字参数
        
    Returns:
        函数执行结果或默认值
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if log_errors:
            center = get_exception_center()
            context = ExceptionContext(
                module_name=func.__module__ if hasattr(func, '__module__') else "unknown",
                function_name=func.__name__ if hasattr(func, '__name__') else "unknown",
                timestamp=time.time(),
                thread_id=threading.get_ident(),
                additional_info={}
            )
            center.handle_exception(e, context)
        
        return default_return