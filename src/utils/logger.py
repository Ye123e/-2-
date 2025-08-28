#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的日志记录器工具模块
提供统一的日志记录功能，包含多种格式化器、处理器和监控功能
"""

import os
import sys
import logging
import logging.handlers
import traceback
import time
import threading
from pathlib import Path
from typing import Optional, Dict, List, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import json
import gzip
from queue import Queue, Empty
from contextlib import contextmanager

@dataclass
class LogConfig:
    """日志配置类"""
    level: str = "INFO"
    log_file: Optional[str] = None
    max_size: str = "10MB"
    backup_count: int = 5
    enable_console: bool = True
    enable_file: bool = True
    enable_json: bool = False
    enable_monitoring: bool = True
    compress_backups: bool = True
    date_format: str = '%Y-%m-%d %H:%M:%S'
    log_format: str = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
    encoding: str = 'utf-8'
    buffer_size: int = 1000
    flush_interval: float = 5.0
    
class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""
    
    # 颜色代码
    COLORS = {
        'DEBUG': '\033[36m',     # 青色
        'INFO': '\033[32m',      # 绿色
        'WARNING': '\033[33m',   # 黄色
        'ERROR': '\033[31m',     # 红色
        'CRITICAL': '\033[35m',  # 紫色
    }
    RESET = '\033[0m'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_colors = self._supports_color()
    
    def _supports_color(self) -> bool:
        """检查终端是否支持颜色"""
        return (
            hasattr(sys.stderr, "isatty") and sys.stderr.isatty() and
            os.environ.get('TERM') != 'dumb'
        )
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        
        return super().format(record)

class JSONFormatter(logging.Formatter):
    """JSON格式化器"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread
        }
        
        # 添加异常信息
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False)

class BufferedFileHandler(logging.handlers.RotatingFileHandler):
    """带缓冲的文件处理器"""
    
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, 
                 encoding=None, delay=False, buffer_size=1000, flush_interval=5.0):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.buffer = Queue(maxsize=buffer_size)
        self.flush_interval = flush_interval
        self.last_flush = time.time()
        self._buffer_lock = threading.Lock()
        
    def emit(self, record):
        try:
            if self.buffer.full():
                self._flush_buffer()
            
            self.buffer.put_nowait(self.format(record))
            
            # 定时刷新
            if time.time() - self.last_flush > self.flush_interval:
                self._flush_buffer()
                
        except Exception:
            self.handleError(record)
    
    def _flush_buffer(self):
        """刷新缓冲区"""
        with self._buffer_lock:
            records = []
            while not self.buffer.empty():
                try:
                    records.append(self.buffer.get_nowait())
                except Empty:
                    break
            
            if records and self.stream:
                for record in records:
                    self.stream.write(record + '\n')
                self.stream.flush()
            
            self.last_flush = time.time()
    
    def close(self):
        self._flush_buffer()
        super().close()

class LogMonitor:
    """日志监控器"""
    
    def __init__(self):
        self.stats = {
            'total_logs': 0,
            'error_count': 0,
            'warning_count': 0,
            'start_time': time.time(),
            'last_error': None,
            'error_rate': 0.0
        }
        self._lock = threading.Lock()
    
    def record_log(self, level: str, message: str):
        """记录日志统计"""
        with self._lock:
            self.stats['total_logs'] += 1
            
            if level == 'ERROR':
                self.stats['error_count'] += 1
                self.stats['last_error'] = {
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }
            elif level == 'WARNING':
                self.stats['warning_count'] += 1
            
            # 计算错误率
            runtime = time.time() - self.stats['start_time']
            if runtime > 0:
                self.stats['error_rate'] = self.stats['error_count'] / runtime * 60  # 每分钟错误数
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            return self.stats.copy()
    
    def is_healthy(self) -> bool:
        """检查日志健康状态"""
        stats = self.get_stats()
        return stats['error_rate'] < 10  # 每分钟少于10个错误

class MonitoringHandler(logging.Handler):
    """监控处理器"""
    
    def __init__(self, monitor: LogMonitor):
        super().__init__()
        self.monitor = monitor
    
    def emit(self, record: logging.LogRecord):
        self.monitor.record_log(record.levelname, record.getMessage())
def parse_size(size_str: str) -> int:
    """解析大小字符串（如10MB）为字节数"""
    size_str = size_str.upper().strip()
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        return int(size_str)

def setup_logger(level: str = "INFO", log_file: Optional[str] = None, 
                config: Optional[LogConfig] = None) -> logging.Logger:
    """
    设置增强的应用程序日志记录器
    
    Args:
        level: 日志级别
        log_file: 日志文件路径
        config: 详细的日志配置
        
    Returns:
        配置好的日志记录器
    """
    if config is None:
        config = LogConfig(level=level, log_file=log_file)
    
    # 创建根日志记录器
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))
    
    # 清除已有的处理器
    logger.handlers.clear()
    
    # 创建监控器
    monitor = LogMonitor() if config.enable_monitoring else None
    
    # 控制台处理器
    if config.enable_console:
        console_handler = logging.StreamHandler()
        
        if config.enable_json:
            console_formatter = JSONFormatter()
        else:
            console_formatter = ColoredFormatter(
                config.log_format,
                datefmt=config.date_format
            )
        
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # 文件处理器
    if config.enable_file and config.log_file:
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        max_bytes = parse_size(config.max_size)
        
        if config.buffer_size > 0:
            file_handler = BufferedFileHandler(
                config.log_file,
                maxBytes=max_bytes,
                backupCount=config.backup_count,
                encoding=config.encoding,
                buffer_size=config.buffer_size,
                flush_interval=config.flush_interval
            )
        else:
            file_handler = logging.handlers.RotatingFileHandler(
                config.log_file,
                maxBytes=max_bytes,
                backupCount=config.backup_count,
                encoding=config.encoding
            )
        
        # 压缩备份文件
        if config.compress_backups:
            file_handler.rotator = _compress_rotator
        
        if config.enable_json:
            file_formatter = JSONFormatter()
        else:
            file_formatter = logging.Formatter(
                config.log_format,
                datefmt=config.date_format
            )
        
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # 监控处理器
    if monitor:
        monitoring_handler = MonitoringHandler(monitor)
        logger.addHandler(monitoring_handler)
        
        # 将监控器附加到logger以便访问
        logger.monitor = monitor
    
    return logger

def _compress_rotator(source, dest):
    """压缩日志轮转文件"""
    try:
        with open(source, 'rb') as f_in:
            with gzip.open(dest + '.gz', 'wb') as f_out:
                f_out.writelines(f_in)
        os.remove(source)
    except Exception as e:
        # 如果压缩失败，保留原文件
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(source, dest)

def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志记录器
    
    Args:
        name: 日志记录器名称
        
    Returns:
        日志记录器实例
    """
    return logging.getLogger(name)

class LoggerMixin:
    """增强的日志记录器混入类"""
    
    @property
    def logger(self) -> logging.Logger:
        """获取当前类的日志记录器"""
        return logging.getLogger(self.__class__.__name__)
    
    def log_method_entry(self, method_name: str, **kwargs):
        """记录方法进入"""
        args_str = ', '.join(f'{k}={v}' for k, v in kwargs.items())
        self.logger.debug(f"进入方法 {method_name}({args_str})")
    
    def log_method_exit(self, method_name: str, result=None, duration=None):
        """记录方法退出"""
        msg = f"退出方法 {method_name}"
        if duration is not None:
            msg += f" (耗时: {duration:.3f}s)"
        if result is not None:
            msg += f" (结果: {result})"
        self.logger.debug(msg)
    
    def log_exception(self, exception: Exception, context: str = ""):
        """记录异常"""
        if context:
            self.logger.error(f"{context}: {str(exception)}", exc_info=True)
        else:
            self.logger.error(f"异常: {str(exception)}", exc_info=True)
    
    @contextmanager
    def log_performance(self, operation: str):
        """性能日志上下文管理器"""
        start_time = time.time()
        self.logger.debug(f"开始执行: {operation}")
        try:
            yield
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"执行失败: {operation} (耗时: {duration:.3f}s)", exc_info=True)
            raise
        else:
            duration = time.time() - start_time
            self.logger.debug(f"执行完成: {operation} (耗时: {duration:.3f}s)")

def get_log_stats() -> Optional[Dict[str, Any]]:
    """获取日志统计信息"""
    root_logger = logging.getLogger()
    if hasattr(root_logger, 'monitor'):
        return root_logger.monitor.get_stats()
    return None

def is_logging_healthy() -> bool:
    """检查日志系统健康状态"""
    root_logger = logging.getLogger()
    if hasattr(root_logger, 'monitor'):
        return root_logger.monitor.is_healthy()
    return True

def create_logger_config_from_dict(config_dict: Dict[str, Any]) -> LogConfig:
    """从字典创建日志配置"""
    return LogConfig(
        level=config_dict.get('level', 'INFO'),
        log_file=config_dict.get('file'),
        max_size=config_dict.get('max_size', '10MB'),
        backup_count=int(config_dict.get('backup_count', 5)),
        enable_console=config_dict.get('enable_console', True),
        enable_file=config_dict.get('enable_file', True),
        enable_json=config_dict.get('enable_json', False),
        enable_monitoring=config_dict.get('enable_monitoring', True),
        compress_backups=config_dict.get('compress_backups', True)
    )