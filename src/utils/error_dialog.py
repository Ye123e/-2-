#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户友好的错误提示和恢复建议系统
提供易懂的错误信息和具体的解决方案
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass
from enum import Enum
import webbrowser
import logging

class ErrorSeverity(Enum):
    """错误严重程度"""
    INFO = "info"
    WARNING = "warning"  
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ErrorSolution:
    """错误解决方案"""
    title: str
    description: str
    steps: List[str]
    auto_fix_available: bool = False
    auto_fix_function: Optional[callable] = None
    external_link: Optional[str] = None

@dataclass
class UserFriendlyError:
    """用户友好的错误信息"""
    title: str
    message: str
    severity: ErrorSeverity
    error_code: str
    technical_details: str
    solutions: List[ErrorSolution]

class ErrorMessageTranslator:
    """错误消息翻译器"""
    
    def __init__(self):
        """初始化错误翻译器"""
        self.translations = self._load_translations()
    
    def _load_translations(self) -> Dict[str, UserFriendlyError]:
        """加载错误翻译映射"""
        return {
            'ImportError': UserFriendlyError(
                title="缺少必要组件",
                message="程序无法找到所需的功能模块，这通常是由于缺少某些软件包造成的。",
                severity=ErrorSeverity.CRITICAL,
                error_code="ERR_001",
                technical_details="ImportError: 无法导入Python模块",
                solutions=[
                    ErrorSolution(
                        title="安装缺失的软件包",
                        description="使用pip安装项目所需的依赖包",
                        steps=[
                            "1. 打开命令提示符或终端",
                            "2. 执行命令: pip install -r requirements.txt",
                            "3. 等待安装完成后重新启动程序"
                        ],
                        auto_fix_available=True
                    )
                ]
            ),
            
            'FileNotFoundError': UserFriendlyError(
                title="文件或目录不存在",
                message="程序无法找到所需的文件或目录。",
                severity=ErrorSeverity.WARNING,
                error_code="ERR_003",
                technical_details="FileNotFoundError: 指定的文件或目录不存在",
                solutions=[
                    ErrorSolution(
                        title="自动创建缺失文件",
                        description="让程序自动创建所需的文件和目录",
                        steps=[
                            "1. 点击'自动修复'按钮",
                            "2. 程序将自动创建必需的目录",
                            "3. 重新启动程序"
                        ],
                        auto_fix_available=True
                    )
                ]
            ),
            
            'PermissionError': UserFriendlyError(
                title="权限不足",
                message="程序没有足够的权限访问某些文件或目录。",
                severity=ErrorSeverity.ERROR,
                error_code="ERR_004",
                technical_details="PermissionError: 权限被拒绝",
                solutions=[
                    ErrorSolution(
                        title="以管理员身份运行",
                        description="使用管理员权限启动程序",
                        steps=[
                            "1. 右键点击程序图标",
                            "2. 选择'以管理员身份运行'",
                            "3. 在弹出的权限确认对话框中点击'是'"
                        ]
                    )
                ]
            ),
            
            'ConnectionError': UserFriendlyError(
                title="网络连接失败",
                message="程序无法建立网络连接。",
                severity=ErrorSeverity.WARNING,
                error_code="ERR_005",
                technical_details="ConnectionError: 连接失败",
                solutions=[
                    ErrorSolution(
                        title="检查网络连接",
                        description="验证网络连接是否正常",
                        steps=[
                            "1. 检查网络连接是否正常",
                            "2. 尝试访问其他网站确认网络可用",
                            "3. 重新尝试操作"
                        ]
                    )
                ]
            ),
            
            'ADBError': UserFriendlyError(
                title="Android调试桥连接失败",
                message="无法连接到Android设备。",
                severity=ErrorSeverity.ERROR,
                error_code="ERR_006",
                technical_details="ADB连接异常",
                solutions=[
                    ErrorSolution(
                        title="启用USB调试",
                        description="在Android设备上启用开发者选项和USB调试",
                        steps=[
                            "1. 在Android设备上打开'设置'",
                            "2. 找到'关于手机'，连续点击'版本号' 7次",
                            "3. 返回设置，进入'开发者选项'",
                            "4. 开启'USB调试'开关"
                        ]
                    )
                ]
            ),
            
            'UnknownError': UserFriendlyError(
                title="未知错误",
                message="程序遇到了一个未知的错误。",
                severity=ErrorSeverity.ERROR,
                error_code="ERR_999",
                technical_details="未分类的异常",
                solutions=[
                    ErrorSolution(
                        title="重启程序",
                        description="尝试重新启动程序解决问题",
                        steps=[
                            "1. 完全关闭程序",
                            "2. 等待5秒后重新启动",
                            "3. 如果问题持续，重启计算机"
                        ]
                    )
                ]
            )
        }
    
    def translate_exception(self, exception: Exception) -> UserFriendlyError:
        """将异常转换为用户友好的错误信息"""
        exception_type = type(exception).__name__
        
        # 特殊处理
        if 'adb' in str(exception).lower() or 'android' in str(exception).lower():
            error_info = self.translations.get('ADBError')
        else:
            error_info = self.translations.get(exception_type, self.translations.get('UnknownError'))
        
        # 确保error_info不为None
        if error_info is None:
            error_info = self.translations['UnknownError']
        
        # 创建一个副本以避免修改原始对象
        from copy import deepcopy
        error_info_copy = deepcopy(error_info)
        
        # 添加具体异常信息
        error_info_copy.technical_details += f"\n详细信息: {str(exception)}"
        
        return error_info_copy

class ErrorDialogManager:
    """错误对话框管理器"""
    
    def __init__(self):
        """初始化错误对话框管理器"""
        self.translator = ErrorMessageTranslator()
        self.logger = logging.getLogger(__name__)
    
    def show_error_dialog(self, exception: Exception, parent=None) -> bool:
        """显示错误对话框"""
        error_info = self.translator.translate_exception(exception)
        return self._create_error_dialog(error_info, parent)
    
    def _create_error_dialog(self, error_info: UserFriendlyError, parent=None) -> bool:
        """创建错误对话框"""
        try:
            # 创建窗口
            if parent:
                dialog = tk.Toplevel(parent)
            else:
                dialog = tk.Tk()
            
            dialog.title(f"错误 - {error_info.title}")
            dialog.geometry("500x400")
            dialog.resizable(True, True)
            
            # 设置样式
            self._setup_dialog_style(dialog, error_info.severity)
            
            # 创建内容
            return self._create_dialog_content(dialog, error_info)
            
        except Exception as e:
            self.logger.error(f"创建错误对话框失败: {e}")
            messagebox.showerror("错误", f"{error_info.title}\n\n{error_info.message}")
            return False
    
    def _setup_dialog_style(self, dialog, severity: ErrorSeverity):
        """设置对话框样式"""
        # 设置窗口居中
        dialog.transient()
        dialog.grab_set()
        
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (250)
        y = (dialog.winfo_screenheight() // 2) - (200)
        dialog.geometry(f"500x400+{x}+{y}")
    
    def _create_dialog_content(self, dialog, error_info: UserFriendlyError) -> bool:
        """创建对话框内容"""
        user_selected_auto_fix = False
        
        # 主框架
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题区域
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 错误图标和标题
        icon_label = ttk.Label(title_frame, text=self._get_severity_icon(error_info.severity), 
                              font=("Arial", 20))
        icon_label.pack(side=tk.LEFT, padx=(0, 10))
        
        title_label = ttk.Label(title_frame, text=error_info.title, 
                               font=("Arial", 12, "bold"))
        title_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 错误描述
        desc_label = ttk.Label(main_frame, text=error_info.message, 
                              font=("Arial", 10), wraplength=450)
        desc_label.pack(anchor=tk.W, pady=(0, 15))
        
        # 解决方案
        solutions_frame = ttk.LabelFrame(main_frame, text="解决方案")
        solutions_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # 滚动文本框显示解决方案
        text_widget = scrolledtext.ScrolledText(solutions_frame, height=8, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加解决方案内容
        for i, solution in enumerate(error_info.solutions):
            text_widget.insert(tk.END, f"方案 {i+1}: {solution.title}\n", "title")
            text_widget.insert(tk.END, f"{solution.description}\n\n", "desc")
            
            for step in solution.steps:
                text_widget.insert(tk.END, f"  {step}\n", "step")
            text_widget.insert(tk.END, "\n")
        
        # 配置文本样式
        text_widget.tag_configure("title", font=("Arial", 10, "bold"))
        text_widget.tag_configure("desc", font=("Arial", 9, "italic"))
        text_widget.tag_configure("step", font=("Arial", 9))
        text_widget.config(state=tk.DISABLED)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_auto_fix():
            nonlocal user_selected_auto_fix
            user_selected_auto_fix = True
            self._execute_auto_fix(error_info.solutions)
            dialog.destroy()
        
        def on_close():
            dialog.destroy()
        
        # 检查是否有自动修复选项
        has_auto_fix = any(solution.auto_fix_available for solution in error_info.solutions)
        
        if has_auto_fix:
            auto_fix_btn = ttk.Button(button_frame, text="自动修复", command=on_auto_fix)
            auto_fix_btn.pack(side=tk.LEFT)
        
        close_btn = ttk.Button(button_frame, text="关闭", command=on_close)
        close_btn.pack(side=tk.RIGHT)
        
        copy_btn = ttk.Button(button_frame, text="复制错误信息", 
                             command=lambda: self._copy_error_info(error_info))
        copy_btn.pack(side=tk.RIGHT, padx=(0, 10))
        
        # 显示对话框
        dialog.wait_window()
        
        return user_selected_auto_fix
    
    def _get_severity_icon(self, severity: ErrorSeverity) -> str:
        """获取严重程度图标"""
        icons = {
            ErrorSeverity.INFO: "ℹ️",
            ErrorSeverity.WARNING: "⚠️",
            ErrorSeverity.ERROR: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }
        return icons.get(severity, "❓")
    
    def _execute_auto_fix(self, solutions: List[ErrorSolution]):
        """执行自动修复"""
        for solution in solutions:
            if solution.auto_fix_available and solution.auto_fix_function:
                try:
                    self.logger.info(f"执行自动修复: {solution.title}")
                    result = solution.auto_fix_function()
                    if result:
                        messagebox.showinfo("修复成功", f"已成功执行: {solution.title}")
                    else:
                        messagebox.showwarning("修复失败", f"修复失败: {solution.title}")
                except Exception as e:
                    self.logger.error(f"自动修复失败: {e}")
                    messagebox.showerror("修复错误", f"自动修复时发生错误: {e}")
    
    def _copy_error_info(self, error_info: UserFriendlyError):
        """复制错误信息到剪贴板"""
        try:
            error_text = f"错误: {error_info.title}\n"
            error_text += f"错误码: {error_info.error_code}\n"
            error_text += f"描述: {error_info.message}\n"
            error_text += f"技术详情: {error_info.technical_details}\n"
            
            # 复制到剪贴板
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(error_text)
            root.update()
            root.destroy()
            
            messagebox.showinfo("复制成功", "错误信息已复制到剪贴板")
            
        except Exception as e:
            self.logger.error(f"复制错误信息失败: {e}")
            messagebox.showerror("复制失败", "无法复制错误信息到剪贴板")

# 便捷函数
def show_user_friendly_error(exception: Exception, parent=None) -> bool:
    """
    显示用户友好的错误对话框
    
    Args:
        exception: 异常对象
        parent: 父窗口
        
    Returns:
        用户是否选择了自动修复
    """
    dialog_manager = ErrorDialogManager()
    return dialog_manager.show_error_dialog(exception, parent)

def create_error_solution(title: str, description: str, steps: List[str],
                         auto_fix_function: Optional[Callable] = None) -> ErrorSolution:
    """
    创建错误解决方案
    
    Args:
        title: 方案标题
        description: 方案描述
        steps: 解决步骤
        auto_fix_function: 自动修复函数
        
    Returns:
        错误解决方案对象
    """
    return ErrorSolution(
        title=title,
        description=description,
        steps=steps,
        auto_fix_available=auto_fix_function is not None,
        auto_fix_function=auto_fix_function
    )

__all__ = ['ErrorDialogManager', 'ErrorSeverity', 'ErrorSolution', 'UserFriendlyError', 
           'show_user_friendly_error', 'create_error_solution']