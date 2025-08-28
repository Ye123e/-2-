#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主窗口GUI界面
使用Tkinter实现的主界面框架
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..config.settings import AppConfig

from ..core.device_manager import DeviceManager
from ..core.diagnostic_engine import DiagnosticEngine
from ..core.security_scanner import SecurityScanner, VirusSignatureDatabase
from ..core.file_manager import FileScanner, FileCleaner
from ..core.repair_engine import RepairEngine, RepairType
from ..models import DeviceInfo, RepairTask
from ..utils.logger import LoggerMixin

class MainWindow(LoggerMixin):
    """主窗口类"""
    
    def __init__(self, config: 'AppConfig') -> None:
        """
        初始化主窗口
        
        Args:
            config: 应用配置对象
        """
        self.config = config
        self.root = tk.Tk()
        self.device_manager = DeviceManager(
            adb_timeout=config.adb_timeout,
            adb_port=config.adb_port,
            adb_path=config.adb_path
        )
        
        # 初始化核心引擎
        self.diagnostic_engine = DiagnosticEngine(self.device_manager)
        
        # 初始化安全扫描器
        signature_db = VirusSignatureDatabase()
        self.security_scanner = SecurityScanner(self.device_manager, signature_db)
        
        # 初始化文件管理器
        self.file_scanner = FileScanner(self.device_manager)
        self.file_cleaner = FileCleaner(self.device_manager)
        
        # 初始化修复引擎
        self.repair_engine = RepairEngine(self.device_manager)
        
        self.current_device: Optional[DeviceInfo] = None
        self.current_diagnostic_report = None
        self.current_virus_report = None
        self.active_repair_tasks = {}
        
        self._setup_window()
        self._create_widgets()
        self._setup_device_callbacks()
        
        # 启动设备监控
        if config.auto_connect:
            self.device_manager.start_monitoring()
    
    def _setup_window(self) -> None:
        """设置窗口属性"""
        self.root.title(f"{self.config.app_name} v{self.config.app_version}")
        self.root.geometry(f"{self.config.window_width}x{self.config.window_height}")
        self.root.resizable(True, True)
        
        # 设置窗口图标（如果存在）
        try:
            # self.root.iconbitmap('icon.ico')  # 需要准备图标文件
            pass
        except:
            pass
        
        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_widgets(self) -> None:
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建标签页
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # 设备连接页面
        self._create_device_tab()
        
        # 系统诊断页面
        self._create_diagnostic_tab()
        
        # 修复操作页面
        self._create_repair_tab()
        
        # 日志查看页面
        self._create_log_tab()
        
        # 状态栏
        self._create_status_bar(main_frame)
    
    def _create_device_tab(self) -> None:
        """创建设备连接标签页"""
        device_frame = ttk.Frame(self.notebook)
        self.notebook.add(device_frame, text="设备连接")
        
        # 设备列表区域
        device_list_frame = ttk.LabelFrame(device_frame, text="连接的设备")
        device_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设备列表
        columns = ("设备ID", "型号", "Android版本", "连接方式", "状态")
        self.device_tree = ttk.Treeview(device_list_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120, anchor="center")
        
        # 滚动条
        device_scrollbar = ttk.Scrollbar(device_list_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=device_scrollbar.set)
        
        # 布局
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        device_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 设备信息区域
        info_frame = ttk.LabelFrame(device_frame, text="设备信息")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.device_info_text = scrolledtext.ScrolledText(info_frame, height=8, state=tk.DISABLED)
        self.device_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 操作按钮区域
        button_frame = ttk.Frame(device_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="刷新设备", command=self._refresh_devices).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="连接设备", command=self._connect_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="断开设备", command=self._disconnect_device).pack(side=tk.LEFT, padx=5)
        
        # 绑定设备选择事件
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
    
    def _create_diagnostic_tab(self) -> None:
        """创建系统诊断标签页"""
        diagnostic_frame = ttk.Frame(self.notebook)
        self.notebook.add(diagnostic_frame, text="系统诊断")
        
        # 诊断控制区域
        control_frame = ttk.LabelFrame(diagnostic_frame, text="诊断控制")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 诊断选项
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.scan_storage = tk.BooleanVar(value=True)
        self.scan_system_files = tk.BooleanVar(value=True)
        self.scan_resources = tk.BooleanVar(value=True)
        self.scan_virus = tk.BooleanVar(value=True)
        self.scan_error_files = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="存储空间检查", variable=self.scan_storage).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="系统文件检查", variable=self.scan_system_files).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="资源扫描", variable=self.scan_resources).grid(row=0, column=2, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="病毒扫描", variable=self.scan_virus).grid(row=1, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="错误文件检查", variable=self.scan_error_files).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # 诊断按钮
        ttk.Button(control_frame, text="开始诊断", command=self._start_diagnostic).pack(pady=10)
        
        # 诊断结果区域
        result_frame = ttk.LabelFrame(diagnostic_frame, text="诊断结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.diagnostic_text = scrolledtext.ScrolledText(result_frame, state=tk.DISABLED)
        self.diagnostic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_repair_tab(self) -> None:
        """创建修复操作标签页"""
        repair_frame = ttk.Frame(self.notebook)
        self.notebook.add(repair_frame, text="修复操作")
        
        # 修复选项区域
        options_frame = ttk.LabelFrame(repair_frame, text="修复选项")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(options_frame, text="一键修复", command=self._auto_repair).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(options_frame, text="清理缓存", command=self._clear_cache).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(options_frame, text="修复权限", command=self._fix_permissions).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(options_frame, text="病毒清除", command=self._remove_virus).pack(side=tk.LEFT, padx=5, pady=5)
        
        # 修复进度区域
        progress_frame = ttk.LabelFrame(repair_frame, text="修复进度")
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.progress_var = tk.StringVar(value="就绪")
        self.progress_label = ttk.Label(progress_frame, textvariable=self.progress_var)
        self.progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # 修复日志区域
        log_frame = ttk.LabelFrame(repair_frame, text="修复日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.repair_log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED)
        self.repair_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_log_tab(self) -> None:
        """创建日志查看标签页"""
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="日志查看")
        
        # 日志控制区域
        control_frame = ttk.Frame(log_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="刷新日志", command=self._refresh_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="清空日志", command=self._clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="保存日志", command=self._save_log).pack(side=tk.LEFT, padx=5)
        
        # 日志显示区域
        self.log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_status_bar(self, parent) -> None:
        """创建状态栏"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X, padx=2, pady=2)
    
    def _setup_device_callbacks(self) -> None:
        """设置设备状态回调"""
        self.device_manager.add_device_callback(self._on_device_change)
        
        # 设置修复引擎回调
        self.repair_engine.add_task_callback(self._on_repair_task_change)
        self.repair_engine.add_progress_callback(self._on_repair_progress)
        
        # 设置诊断引擎回调
        self.diagnostic_engine.add_progress_callback(self._on_diagnostic_progress)
        
        # 设置安全扫描器回调
        self.security_scanner.add_progress_callback(self._on_security_progress)
    
    def _on_device_change(self, action: str, device_info: DeviceInfo):
        """设备状态变化回调"""
        self.root.after(0, self._update_device_list)
        
        if action == 'connected':
            self.root.after(0, lambda: self._set_status(f"设备已连接: {device_info.model}"))
        elif action == 'disconnected':
            self.root.after(0, lambda: self._set_status(f"设备已断开: {device_info.model}"))
    
    def _on_repair_task_change(self, task: RepairTask):
        """修复任务状态变化回调"""
        def update_ui():
            self.active_repair_tasks[task.task_id] = task
            self._update_repair_status(task)
        
        self.root.after(0, update_ui)
    
    def _on_repair_progress(self, task_id: str, progress: int, message: str):
        """修复进度回调"""
        def update_ui():
            self.progress_bar['value'] = progress
            self.progress_var.set(message)
            self._append_repair_log(f"[{progress}%] {message}")
        
        self.root.after(0, update_ui)
    
    def _on_diagnostic_progress(self, progress: int, message: str):
        """诊断进度回调"""
        def update_ui():
            self._append_diagnostic_result(f"[{progress}%] {message}")
        
        self.root.after(0, update_ui)
    
    def _on_security_progress(self, progress: int, message: str):
        """安全扫描进度回调"""
        def update_ui():
            self._append_diagnostic_result(f"[安全扫描 {progress}%] {message}")
        
        self.root.after(0, update_ui)
    
    def _refresh_devices(self):
        """刷新设备列表"""
        def scan_devices():
            self._set_status("正在扫描设备...")
            self.device_manager.scan_devices()
            self.root.after(0, self._update_device_list)
            self.root.after(0, lambda: self._set_status("设备扫描完成"))
        
        threading.Thread(target=scan_devices, daemon=True).start()
    
    def _update_device_list(self):
        """更新设备列表显示"""
        # 清空当前列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # 添加设备信息
        devices = self.device_manager.get_connected_devices()
        for device in devices:
            self.device_tree.insert("", tk.END, values=(
                device.device_id,
                device.model,
                device.android_version,
                device.connection_type.value,
                "已连接"
            ))
    
    def _on_device_select(self, event):
        """设备选择事件处理"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            device_id = item['values'][0]
            self.current_device = self.device_manager.get_device(device_id)
            self._update_device_info()
    
    def _update_device_info(self):
        """更新设备信息显示"""
        self.device_info_text.config(state=tk.NORMAL)
        self.device_info_text.delete(1.0, tk.END)
        
        if self.current_device:
            info = f"""设备信息：
设备ID: {self.current_device.device_id}
型号: {self.current_device.model}
制造商: {self.current_device.manufacturer}
Android版本: {self.current_device.android_version}
编译版本: {self.current_device.build_number}
CPU架构: {self.current_device.cpu_arch}
屏幕分辨率: {self.current_device.screen_resolution}
ROOT状态: {'已获取' if self.current_device.root_status else '未获取'}
连接方式: {self.current_device.connection_type.value}
存储空间: {self.current_device.storage_free / (1024**3):.1f}GB 可用 / {self.current_device.storage_total / (1024**3):.1f}GB 总计
存储使用率: {self.current_device.storage_usage_percent:.1f}%
最后连接: {self.current_device.last_connected.strftime('%Y-%m-%d %H:%M:%S') if self.current_device.last_connected else '未知'}"""
            self.device_info_text.insert(1.0, info)
        
        self.device_info_text.config(state=tk.DISABLED)
    
    def _connect_device(self):
        """连接设备"""
        self._set_status("正在连接设备...")
        # 这里可以添加手动连接设备的逻辑
        self._refresh_devices()
    
    def _disconnect_device(self):
        """断开设备"""
        if self.current_device:
            self.device_manager.disconnect_device(self.current_device.device_id)
            self._set_status(f"已断开设备: {self.current_device.model}")
            self.current_device = None
            self._update_device_info()
    
    def _start_diagnostic(self):
        """开始系统诊断"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # 获取诊断选项
        options = {
            'storage': self.scan_storage.get(),
            'system_files': self.scan_system_files.get(),
            'resources': self.scan_resources.get(),
            'virus': self.scan_virus.get(),
            'error_files': self.scan_error_files.get()
        }
        
        self.diagnostic_text.config(state=tk.NORMAL)
        self.diagnostic_text.delete(1.0, tk.END)
        self.diagnostic_text.insert(tk.END, "开始系统诊断...\n")
        self.diagnostic_text.config(state=tk.DISABLED)
        
        # 在新线程中执行诊断
        def run_diagnostic():
            try:
                self._set_status("正在执行系统诊断...")
                
                # 执行诊断
                report = self.diagnostic_engine.diagnose_device(self.current_device.device_id, options)
                
                if report:
                    self.current_diagnostic_report = report
                    self.root.after(0, lambda: self._display_diagnostic_report(report))
                    self.root.after(0, lambda: self._set_status(“诊断完成"))
                else:
                    self.root.after(0, lambda: self._append_diagnostic_result("诊断失败"))
                    self.root.after(0, lambda: self._set_status("诊断失败"))
                
            except Exception as e:
                self.root.after(0, lambda: self._append_diagnostic_result(f"诊断异常: {str(e)}"))
                self.root.after(0, lambda: self._set_status("诊断异常"))
                self.logger.error(f"诊断异常: {e}")
        
        threading.Thread(target=run_diagnostic, daemon=True).start()
    
    def _display_diagnostic_report(self, report):
        """显示诊断报告"""
        self.diagnostic_text.config(state=tk.NORMAL)
        self.diagnostic_text.delete(1.0, tk.END)
        
        # 显示系统健康评分
        self.diagnostic_text.insert(tk.END, f"系统健康评分: {report.system_health_score}/100\n\n")
        
        # 显示问题统计
        self.diagnostic_text.insert(tk.END, f"发现问题: {report.total_issues_count}个\n")
        self.diagnostic_text.insert(tk.END, f"关键问题: {report.critical_issues_count}个\n")
        self.diagnostic_text.insert(tk.END, f"高优先级问题: {report.high_issues_count}个\n\n")
        
        # 显示具体问题
        if report.issues_found:
            self.diagnostic_text.insert(tk.END, "发现的问题:\n")
            for i, issue in enumerate(report.issues_found[:10], 1):  # 只显示前10个
                severity_text = {
                    'CRITICAL': '关键',
                    'HIGH': '高',
                    'MEDIUM': '中',
                    'LOW': '低'
                }.get(issue.severity.value, issue.severity.value)
                
                auto_fix_text = "可自动修复" if issue.auto_fixable else "需手动处理"
                
                self.diagnostic_text.insert(tk.END, 
                    f"{i}. [{severity_text}] {issue.description} ({auto_fix_text})\n")
            
            if len(report.issues_found) > 10:
                self.diagnostic_text.insert(tk.END, f"···还有 {len(report.issues_found) - 10} 个问题\n")
        
        # 显示修复建议
        if report.recommendations:
            self.diagnostic_text.insert(tk.END, "\n修复建议:\n")
            for i, recommendation in enumerate(report.recommendations, 1):
                self.diagnostic_text.insert(tk.END, f"{i}. {recommendation}\n")
        
        self.diagnostic_text.config(state=tk.DISABLED)
    
    def _append_diagnostic_result(self, message: str):
        """附加诊断结果消息"""
        self.diagnostic_text.config(state=tk.NORMAL)
        self.diagnostic_text.insert(tk.END, f"{message}\n")
        self.diagnostic_text.see(tk.END)
        self.diagnostic_text.config(state=tk.DISABLED)
    
    def _update_repair_status(self, task: RepairTask):
        """更新修复状态"""
        status_text = {
            'PENDING': '等待中',
            'RUNNING': '正在执行',
            'COMPLETED': '已完成',
            'FAILED': '已失败',
            'CANCELLED': '已取消'
        }.get(task.status.value, task.status.value)
        
        self.progress_var.set(f"任务状态: {status_text}")
        
        if task.status.value == 'COMPLETED':
            self.progress_bar['value'] = 100
            self._set_status("修复任务完成")
        elif task.status.value == 'FAILED':
            self._set_status(f"修复任务失败: {task.error_message}")
    
    def _append_repair_log(self, message: str):
        """附加修复日志"""
        self.repair_log_text.config(state=tk.NORMAL)
        self.repair_log_text.insert(tk.END, f"{message}\n")
        self.repair_log_text.see(tk.END)
        self.repair_log_text.config(state=tk.DISABLED)
    
    def _auto_repair(self):
        """一键自动修复"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # 创建全面修复任务
        task_id = self.repair_engine.create_repair_plan(
            self.current_device.device_id,
            RepairType.FULL_REPAIR
        )
        
        if task_id:
            # 执行修复任务
            success = self.repair_engine.execute_repair(task_id)
            if success:
                self._set_status("已启动一键修复任务")
                self._append_repair_log("启动一键修复任务...")
            else:
                self._set_status("启动修复任务失败")
        else:
            self._set_status("创建修复任务失败")
    
    def _clear_cache(self):
        """清理缓存"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # 创建缓存清理任务
        task_id = self.repair_engine.create_repair_plan(
            self.current_device.device_id,
            RepairType.CACHE_CLEAR
        )
        
        if task_id:
            success = self.repair_engine.execute_repair(task_id)
            if success:
                self._set_status("已启动缓存清理任务")
                self._append_repair_log("启动缓存清理任务...")
            else:
                self._set_status("启动缓存清理任务失败")
        else:
            self._set_status("创建缓存清理任务失败")
    
    def _fix_permissions(self):
        """修复权限"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        if not self.current_device.root_status:
            messagebox.showwarning("警告", "权限修复需要ROOT权限")
            return
        
        # 创建权限修复任务
        task_id = self.repair_engine.create_repair_plan(
            self.current_device.device_id,
            RepairType.PERMISSION_FIX
        )
        
        if task_id:
            success = self.repair_engine.execute_repair(task_id)
            if success:
                self._set_status("已启动权限修复任务")
                self._append_repair_log("启动权限修复任务...")
            else:
                self._set_status("启动权限修复任务失败")
        else:
            self._set_status("创建权限修复任务失败")
    
    def _remove_virus(self):
        """清除病毒"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # 创建病毒清除任务
        task_id = self.repair_engine.create_repair_plan(
            self.current_device.device_id,
            RepairType.VIRUS_REMOVAL
        )
        
        if task_id:
            success = self.repair_engine.execute_repair(task_id)
            if success:
                self._set_status("已启动病毒清除任务")
                self._append_repair_log("启动病毒清除任务...")
            else:
                self._set_status("启动病毒清除任务失败")
        else:
            self._set_status("创建病毒清除任务失败")
    
    def _refresh_log(self):
        """刷新日志"""
        self._set_status("日志刷新功能开发中...")
    
    def _clear_log(self):
        """清空日志"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def _save_log(self):
        """保存日志"""
        self._set_status("日志保存功能开发中...")
    
    def _set_status(self, message: str):
        """设置状态栏消息"""
        self.status_var.set(message)
        self.logger.info(message)
    
    def _on_closing(self) -> None:
        """窗口关闭事件处理"""
        self.device_manager.stop_monitoring()
        self.root.quit()
        self.root.destroy()
    
    def run(self) -> None:
        """运行主界面"""
        self.logger.info("启动主界面")
        self._set_status("Android系统修复工具已启动")
        self.root.mainloop()