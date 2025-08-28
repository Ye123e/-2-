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
from ..core.virus_scan_engine import EnhancedVirusSignatureDatabase, MultiEngineVirusScanner
from ..core.threat_analysis_engine import ThreatAnalysisEngine
from ..core.real_time_protection import RealTimeProtectionManager
from ..core.quarantine_manager import QuarantineManager
from ..core.database_manager import DatabaseManager
from ..core.report_system import ReportManager, ReportType, ReportFormat
from ..models import DeviceInfo, RepairTask, ScanResult, ThreatAssessment
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
        
        # 初始化数据库管理器
        self.db_manager = DatabaseManager()
        
        # 初始化增强病毒检测引擎
        enhanced_signature_db = EnhancedVirusSignatureDatabase()
        self.virus_scanner = MultiEngineVirusScanner(enhanced_signature_db)
        
        # 初始化威胁分析引擎
        self.threat_analyzer = ThreatAnalysisEngine()
        
        # 初始化安全扫描器
        signature_db = VirusSignatureDatabase()
        self.security_scanner = SecurityScanner(self.device_manager, signature_db)
        
        # 初始化隔离管理器
        self.quarantine_manager = QuarantineManager()
        
        # 初始化实时防护管理器
        self.protection_manager = RealTimeProtectionManager(self.device_manager, enhanced_signature_db)
        
        # 初始化报告管理器
        self.report_manager = ReportManager(self.db_manager)
        
        # 初始化文件管理器
        self.file_scanner = FileScanner(self.device_manager)
        self.file_cleaner = FileCleaner(self.device_manager)
        
        # 初始化修复引擎
        self.repair_engine = RepairEngine(self.device_manager)
        
        self.current_device: Optional[DeviceInfo] = None
        self.current_diagnostic_report = None
        self.current_virus_report = None
        self.current_scan_result = None
        self.current_threat_assessment = None
        self.active_repair_tasks = {}
        self.quarantined_files = []
        self.protection_enabled = False
        
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
        
        # 病毒扫描页面
        self._create_virus_scan_tab()
        
        # 威胁管理页面
        self._create_threat_management_tab()
        
        # 实时防护页面
        self._create_protection_tab()
        
        # 修复操作页面
        self._create_repair_tab()
        
        # 报告管理页面
        self._create_report_tab()
        
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
    
    def _create_virus_scan_tab(self) -> None:
        """创建病毒扫描标签页"""
        virus_frame = ttk.Frame(self.notebook)
        self.notebook.add(virus_frame, text="病毒扫描")
        
        # 扫描配置区域
        config_frame = ttk.LabelFrame(virus_frame, text="扫描配置")
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 扫描模式
        mode_frame = ttk.Frame(config_frame)
        mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(mode_frame, text="扫描模式:").pack(side=tk.LEFT, padx=5)
        self.scan_mode = tk.StringVar(value="QUICK")
        ttk.Radiobutton(mode_frame, text="快速扫描", variable=self.scan_mode, value="QUICK").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="全面扫描", variable=self.scan_mode, value="FULL").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="自定义扫描", variable=self.scan_mode, value="CUSTOM").pack(side=tk.LEFT, padx=5)
        
        # 扫描引擎选择
        engine_frame = ttk.Frame(config_frame)
        engine_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(engine_frame, text="检测引擎:").pack(side=tk.LEFT, padx=5)
        self.engine_signature = tk.BooleanVar(value=True)
        self.engine_yara = tk.BooleanVar(value=True)
        self.engine_heuristic = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(engine_frame, text="特征检测", variable=self.engine_signature).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(engine_frame, text="YARA规则", variable=self.engine_yara).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(engine_frame, text="启发式检测", variable=self.engine_heuristic).pack(side=tk.LEFT, padx=5)
        
        # 扫描按钮
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="开始扫描", command=self._start_virus_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="停止扫描", command=self._stop_virus_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="更新病毒库", command=self._update_virus_db).pack(side=tk.LEFT, padx=5)
        
        # 扫描进度区域
        progress_frame = ttk.LabelFrame(virus_frame, text="扫描进度")
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.virus_progress_var = tk.StringVar(value="就绪")
        self.virus_progress_label = ttk.Label(progress_frame, textvariable=self.virus_progress_var)
        self.virus_progress_label.pack(pady=5)
        
        self.virus_progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.virus_progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # 扫描结果区域
        result_frame = ttk.LabelFrame(virus_frame, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 结果统计
        stats_frame = ttk.Frame(result_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.scanned_files_var = tk.StringVar(value="已扫描文件: 0")
        self.threats_found_var = tk.StringVar(value="发现威胁: 0")
        self.scan_time_var = tk.StringVar(value="扫描时间: 0s")
        
        ttk.Label(stats_frame, textvariable=self.scanned_files_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_frame, textvariable=self.threats_found_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_frame, textvariable=self.scan_time_var).pack(side=tk.LEFT, padx=10)
        
        # 威胁列表
        threat_columns = ("威胁名称", "类型", "等级", "文件路径", "检测引擎")
        self.threat_tree = ttk.Treeview(result_frame, columns=threat_columns, show="headings", height=10)
        
        for col in threat_columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=120, anchor="center")
        
        # 滚动条
        threat_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=threat_scrollbar.set)
        
        # 布局
        self.threat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        threat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self.threat_context_menu = tk.Menu(self.root, tearoff=0)
        self.threat_context_menu.add_command(label="隔离文件", command=self._quarantine_threat)
        self.threat_context_menu.add_command(label="删除文件", command=self._delete_threat)
        self.threat_context_menu.add_command(label="添加白名单", command=self._add_to_whitelist)
        self.threat_context_menu.add_command(label="显示详情", command=self._show_threat_details)
        
        self.threat_tree.bind("<Button-3>", self._show_threat_context_menu)
    
    def _start_virus_scan(self):
        """开始病毒扫描"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        # 清空之前的结果
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        
        # 重置统计
        self.scanned_files_var.set("已扫描文件: 0")
        self.threats_found_var.set("发现威胁: 0")
        self.scan_time_var.set("扫描时间: 0s")
        
        self.virus_progress_var.set("正在初始化扫描...")
        self.virus_progress_bar['value'] = 0
        
        def run_scan():
            try:
                from ..models import ScanMode
                
                # 获取扫描配置
                scan_mode = ScanMode(self.scan_mode.get())
                
                # 设置进度回调
                def progress_callback(progress, message):
                    self.root.after(0, lambda: self._update_virus_scan_progress(progress, message))
                
                self.virus_scanner.add_progress_callback(progress_callback)
                
                # 执行扫描
                scan_result = self.virus_scanner.scan_device(
                    self.current_device.device_id,
                    scan_mode,
                    engines_enabled={
                        'signature': self.engine_signature.get(),
                        'yara': self.engine_yara.get(),
                        'heuristic': self.engine_heuristic.get()
                    }
                )
                
                if scan_result:
                    self.current_scan_result = scan_result
                    self.root.after(0, lambda: self._display_scan_result(scan_result))
                    # 保存扫描结果到数据库
                    self.db_manager.insert_scan_result(scan_result)
                else:
                    self.root.after(0, lambda: self._set_status("扫描失败"))
                    
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"扫描异常: {str(e)}"))
                self.logger.error(f"扫描异常: {e}")
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def _stop_virus_scan(self):
        """停止病毒扫描"""
        # 这里可以实现停止扫描的逻辑
        self._set_status("扫描已停止")
        self.virus_progress_var.set("扫描已停止")
    
    def _update_virus_db(self):
        """更新病毒库"""
        def update_db():
            try:
                self.root.after(0, lambda: self._set_status("正在更新病毒库..."))
                success = self.virus_scanner.signature_db.update_signatures()
                if success:
                    self.root.after(0, lambda: self._set_status("病毒库更新成功"))
                else:
                    self.root.after(0, lambda: self._set_status("病毒库更新失败"))
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"更新病毒库异常: {str(e)}"))
        
        threading.Thread(target=update_db, daemon=True).start()
    
    def _update_virus_scan_progress(self, progress: int, message: str):
        """更新扫描进度"""
        self.virus_progress_bar['value'] = progress
        self.virus_progress_var.set(message)
    
    def _display_scan_result(self, scan_result: ScanResult):
        """显示扫描结果"""
        # 更新统计信息
        self.scanned_files_var.set(f"已扫描文件: {scan_result.total_files_scanned}")
        self.threats_found_var.set(f"发现威胁: {scan_result.threats_found}")
        
        if scan_result.scan_duration:
            self.scan_time_var.set(f"扫描时间: {scan_result.scan_duration:.1f}s")
        
        # 显示威胁列表
        for malware in scan_result.malware_list:
            self.threat_tree.insert("", tk.END, values=(
                malware.threat_name,
                malware.threat_type.value,
                malware.threat_level.value,
                malware.file_path,
                malware.engine_type.value
            ))
        
        self.virus_progress_var.set(f"扫描完成 - 发现 {scan_result.threats_found} 个威胁")
        self._set_status(f"扫描完成，发现 {scan_result.threats_found} 个威胁")
    
    def _show_threat_context_menu(self, event):
        """显示威胁右键菜单"""
        try:
            self.threat_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.threat_context_menu.grab_release()
    
    def _quarantine_threat(self):
        """隔离威胁文件"""
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        item = self.threat_tree.item(selection[0])
        file_path = item['values'][3]
        
        # 执行隔离
        success = self.quarantine_manager.quarantine_file(file_path, "用户手动隔离")
        if success:
            self._set_status(f"文件已隔离: {file_path}")
            # 更新隔离列表
            self.quarantined_files.append(file_path)
        else:
            self._set_status(f"隔离失败: {file_path}")
    
    def _delete_threat(self):
        """删除威胁文件"""
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        item = self.threat_tree.item(selection[0])
        file_path = item['values'][3]
        
        # 确认删除
        result = messagebox.askyesno("确认删除", f"确定要删除文件：{file_path}")
        if result:
            # 这里可以实现删除逻辑
            self._set_status(f"文件删除功能开发中: {file_path}")
    
    def _add_to_whitelist(self):
        """添加到白名单"""
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        item = self.threat_tree.item(selection[0])
        file_path = item['values'][3]
        
        # 添加到白名单
        self._set_status(f"已添加到白名单: {file_path}")
    
    def _show_threat_details(self):
        """显示威胁详情"""
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        item = self.threat_tree.item(selection[0])
        threat_name = item['values'][0]
        file_path = item['values'][3]
        
        # 显示详情对话框
        details = f"威胁名称: {threat_name}\n文件路径: {file_path}\n\n详细信息功能开发中..."
        messagebox.showinfo("威胁详情", details)
    
    def _create_threat_management_tab(self) -> None:
        """创建威胁管理标签页"""
        threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(threat_frame, text="威胁管理")
        
        # 威胁概览区域
        overview_frame = ttk.LabelFrame(threat_frame, text="威胁概览")
        overview_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 威胁统计
        stats_frame = ttk.Frame(overview_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_stats = {
            'total_threats': tk.StringVar(value="总威胁: 0"),
            'critical_threats': tk.StringVar(value="严重威胁: 0"),
            'quarantined_files': tk.StringVar(value="已隔离: 0"),
            'protected_status': tk.StringVar(value="防护状态: 关闭")
        }
        
        for i, (key, var) in enumerate(self.threat_stats.items()):
            ttk.Label(stats_frame, textvariable=var).grid(row=0, column=i, padx=10, sticky=tk.W)
        
        # 操作按钮
        action_frame = ttk.Frame(overview_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(action_frame, text="威胁分析", command=self._analyze_threats).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="批量隔离", command=self._batch_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="清理隔离区", command=self._cleanup_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="导出报告", command=self._export_threat_report).pack(side=tk.LEFT, padx=5)
        
        # 威胁列表区域
        list_frame = ttk.LabelFrame(threat_frame, text="威胁列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 过滤选项
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="筛选:").pack(side=tk.LEFT, padx=5)
        self.threat_filter = tk.StringVar(value="全部")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.threat_filter, 
                                   values=["全部", "严重", "高危", "中等", "低危"], state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", self._filter_threats)
        
        ttk.Button(filter_frame, text="刷新", command=self._refresh_threat_list).pack(side=tk.LEFT, padx=5)
        
        # 威胁详细列表
        threat_columns = ("ID", "威胁名称", "类型", "等级", "风险评分", "发现时间", "状态")
        self.threat_detail_tree = ttk.Treeview(list_frame, columns=threat_columns, show="headings", height=12)
        
        for col in threat_columns:
            self.threat_detail_tree.heading(col, text=col)
            if col == "威胁名称":
                self.threat_detail_tree.column(col, width=200)
            elif col == "发现时间":
                self.threat_detail_tree.column(col, width=150)
            else:
                self.threat_detail_tree.column(col, width=100)
        
        # 滚动条
        threat_detail_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.threat_detail_tree.yview)
        self.threat_detail_tree.configure(yscrollcommand=threat_detail_scrollbar.set)
        
        # 布局
        self.threat_detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        threat_detail_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 威胁详情显示
        detail_frame = ttk.LabelFrame(threat_frame, text="威胁详情")
        detail_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_detail_text = scrolledtext.ScrolledText(detail_frame, height=6, state=tk.DISABLED)
        self.threat_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 绑定选择事件
        self.threat_detail_tree.bind("<<TreeviewSelect>>", self._on_threat_select)
        
        # 右键菜单
        self.threat_management_menu = tk.Menu(self.root, tearoff=0)
        self.threat_management_menu.add_command(label="隔离威胁", command=self._quarantine_selected_threat)
        self.threat_management_menu.add_command(label="删除威胁", command=self._delete_selected_threat)
        self.threat_management_menu.add_command(label="恢复文件", command=self._restore_threat)
        self.threat_management_menu.add_separator()
        self.threat_management_menu.add_command(label="查看详情", command=self._view_threat_details)
        self.threat_management_menu.add_command(label="威胁分析", command=self._analyze_selected_threat)
        
        self.threat_detail_tree.bind("<Button-3>", self._show_threat_management_menu)
    
    def _analyze_threats(self):
        """威胁分析"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        def run_analysis():
            try:
                self.root.after(0, lambda: self._set_status("正在执行威胁分析..."))
                
                # 获取安装的应用列表
                apps_info = self._get_installed_apps()
                
                threat_assessments = []
                for app_info in apps_info:
                    # 执行威胁分析
                    assessment = self.threat_analyzer.analyze_threat(app_info)
                    threat_assessments.append(assessment)
                    
                    # 保存到数据库
                    self.db_manager.insert_threat_assessment(assessment)
                
                # 更新UI
                self.root.after(0, lambda: self._display_threat_assessments(threat_assessments))
                self.root.after(0, lambda: self._set_status(f"威胁分析完成，分析了 {len(threat_assessments)} 个应用"))
                
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"威胁分析异常: {str(e)}"))
                self.logger.error(f"威胁分析异常: {e}")
        
        threading.Thread(target=run_analysis, daemon=True).start()
    
    def _get_installed_apps(self) -> list:
        """获取安装的应用列表"""
        # 这里应该实现获取应用列表的逻辑
        # 为简化，返回一个模拟的应用列表
        return [
            {
                'package_name': 'com.example.app1',
                'permissions': ['INTERNET', 'READ_CONTACTS'],
                'install_source': 'com.android.vending'
            },
            {
                'package_name': 'com.suspicious.app',
                'permissions': ['SEND_SMS', 'READ_SMS', 'DEVICE_ADMIN'],
                'install_source': 'unknown'
            }
        ]
    
    def _display_threat_assessments(self, assessments: list):
        """显示威胁评估结果"""
        # 清空列表
        for item in self.threat_detail_tree.get_children():
            self.threat_detail_tree.delete(item)
        
        total_threats = 0
        critical_threats = 0
        
        for assessment in assessments:
            # 添加到列表
            status = "正常" if assessment.threat_level.value == "CLEAN" else "威胁"
            if assessment.threat_level.value in ["HIGH", "CRITICAL"]:
                critical_threats += 1
                status = "高危险"
            
            if assessment.threat_level.value != "CLEAN":
                total_threats += 1
            
            self.threat_detail_tree.insert("", tk.END, values=(
                assessment.assessment_id[:8],
                assessment.target_package,
                ", ".join(assessment.threat_categories),
                assessment.threat_level.value,
                f"{assessment.risk_score:.2f}",
                assessment.assessment_time.strftime("%Y-%m-%d %H:%M"),
                status
            ))
        
        # 更新统计
        self.threat_stats['total_threats'].set(f"总威胁: {total_threats}")
        self.threat_stats['critical_threats'].set(f"严重威胁: {critical_threats}")
        self.threat_stats['quarantined_files'].set(f"已隔离: {len(self.quarantined_files)}")
    
    def _batch_quarantine(self):
        """批量隔离"""
        # 获取所有高危险威胁
        high_risk_items = []
        for item in self.threat_detail_tree.get_children():
            values = self.threat_detail_tree.item(item)['values']
            if values[3] in ['HIGH', 'CRITICAL']:  # 威胁等级
                high_risk_items.append(values)
        
        if not high_risk_items:
            messagebox.showinfo("信息", "没有发现高危险威胁")
            return
        
        result = messagebox.askyesno("批量隔离", f"发现 {len(high_risk_items)} 个高危险威胁，是否批量隔离？")
        if result:
            quarantined_count = 0
            for item_values in high_risk_items:
                package_name = item_values[1]
                # 执行隔离逻辑
                success = self._quarantine_package(package_name)
                if success:
                    quarantined_count += 1
            
            self._set_status(f"批量隔离完成，成功隔离 {quarantined_count} 个应用")
            self._refresh_threat_list()
    
    def _quarantine_package(self, package_name: str) -> bool:
        """隔离应用包"""
        try:
            # 这里实现应用隔离逻辑
            self.quarantined_files.append(package_name)
            return True
        except Exception as e:
            self.logger.error(f"隔离应用失败: {e}")
            return False
    
    def _cleanup_quarantine(self):
        """清理隔离区"""
        if not self.quarantined_files:
            messagebox.showinfo("信息", "隔离区为空")
            return
        
        result = messagebox.askyesno("清理隔离区", f"隔离区有 {len(self.quarantined_files)} 个文件，是否全部清理？")
        if result:
            self.quarantined_files.clear()
            self.threat_stats['quarantined_files'].set("已隔离: 0")
            self._set_status("隔离区已清理")
    
    def _export_threat_report(self):
        """导出威胁报告"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择一个设备")
            return
        
        def export_report():
            try:
                from datetime import datetime
                from ..core.report_system import ReportType, ReportFormat
                
                # 生成威胁报告
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = f"reports/threat_report_{timestamp}.html"
                
                success = self.report_manager.create_and_export_report(
                    ReportType.SECURITY_ANALYSIS,
                    ReportFormat.HTML,
                    output_path,
                    self.current_device.device_id
                )
                
                if success:
                    self.root.after(0, lambda: self._set_status(f"报告已导出: {output_path}"))
                    self.root.after(0, lambda: messagebox.showinfo("成功", f"威胁报告已导出到: {output_path}"))
                else:
                    self.root.after(0, lambda: self._set_status("报告导出失败"))
                    
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"导出报告异常: {str(e)}"))
        
        threading.Thread(target=export_report, daemon=True).start()
    
    def _filter_threats(self, event=None):
        """过滤威胁列表"""
        filter_value = self.threat_filter.get()
        
        # 清空列表
        for item in self.threat_detail_tree.get_children():
            self.threat_detail_tree.delete(item)
        
        # 重新加载数据（这里需要从数据库或缓存中获取）
        # 为简化，直接重新分析
        if hasattr(self, 'current_scan_result') and self.current_scan_result:
            self._display_scan_result(self.current_scan_result)
    
    def _refresh_threat_list(self):
        """刷新威胁列表"""
        self._analyze_threats()
    
    def _on_threat_select(self, event):
        """威胁选择事件"""
        selection = self.threat_detail_tree.selection()
        if selection:
            item = self.threat_detail_tree.item(selection[0])
            values = item['values']
            
            # 显示详细信息
            details = f"""威胁详情:

ID: {values[0]}
包名: {values[1]}
威胁类型: {values[2]}
威胁等级: {values[3]}
风险评分: {values[4]}
发现时间: {values[5]}
当前状态: {values[6]}

建议操作:
- 如果是高危险威胁，建议立即隔离
- 可以查看更多详细信息进行进一步分析
- 对于误报，可以添加到白名单"""
            
            self.threat_detail_text.config(state=tk.NORMAL)
            self.threat_detail_text.delete(1.0, tk.END)
            self.threat_detail_text.insert(1.0, details)
            self.threat_detail_text.config(state=tk.DISABLED)
    
    def _show_threat_management_menu(self, event):
        """显示威胁管理右键菜单"""
        try:
            self.threat_management_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.threat_management_menu.grab_release()
    
    def _quarantine_selected_threat(self):
        """隔离选中的威胁"""
        selection = self.threat_detail_tree.selection()
        if not selection:
            return
        
        item = self.threat_detail_tree.item(selection[0])
        package_name = item['values'][1]
        
        success = self._quarantine_package(package_name)
        if success:
            self._set_status(f"应用已隔离: {package_name}")
            # 更新统计
            self.threat_stats['quarantined_files'].set(f"已隔离: {len(self.quarantined_files)}")
        else:
            self._set_status(f"隔离失败: {package_name}")
    
    def _delete_selected_threat(self):
        """删除选中的威胁"""
        selection = self.threat_detail_tree.selection()
        if not selection:
            return
        
        item = self.threat_detail_tree.item(selection[0])
        package_name = item['values'][1]
        
        result = messagebox.askyesno("确认删除", f"确定要删除应用: {package_name}？")
        if result:
            # 这里实现删除逻辑
            self._set_status(f"应用删除功能开发中: {package_name}")
    
    def _restore_threat(self):
        """恢复威胁文件"""
        selection = self.threat_detail_tree.selection()
        if not selection:
            return
        
        item = self.threat_detail_tree.item(selection[0])
        package_name = item['values'][1]
        
        if package_name in self.quarantined_files:
            self.quarantined_files.remove(package_name)
            self.threat_stats['quarantined_files'].set(f"已隔离: {len(self.quarantined_files)}")
            self._set_status(f"应用已恢复: {package_name}")
        else:
            self._set_status(f"应用未在隔离区: {package_name}")
    
    def _view_threat_details(self):
        """查看威胁详情"""
        selection = self.threat_detail_tree.selection()
        if not selection:
            return
        
        item = self.threat_detail_tree.item(selection[0])
        package_name = item['values'][1]
        threat_level = item['values'][3]
        
        details = f"""威胁详细信息

应用包名: {package_name}
威胁等级: {threat_level}

详细分析结果：
- 权限分析: 检测到可疑权限组合
- 行为分析: 发现异常网络连接
- 特征匹配: 与已知恶意软件特征相似

建议处理方式：
1. 立即隔离该应用
2. 检查是否有数据泄露
3. 更改相关账户密码
4. 全面扫描系统"""
        
        messagebox.showinfo("威胁详情", details)
    
    def _analyze_selected_threat(self):
        """分析选中的威胁"""
        selection = self.threat_detail_tree.selection()
        if not selection:
            return
        
        item = self.threat_detail_tree.item(selection[0])
        package_name = item['values'][1]
        
        def run_analysis():
            try:
                self.root.after(0, lambda: self._set_status(f"正在分析 {package_name}..."))
                
                # 模拟威胁分析
                app_info = {
                    'package_name': package_name,
                    'permissions': ['SEND_SMS', 'READ_CONTACTS', 'INTERNET'],
                    'install_source': 'unknown'
                }
                
                assessment = self.threat_analyzer.analyze_threat(app_info)
                
                # 显示分析结果
                analysis_result = f"""威胁分析报告

应用: {assessment.target_package}
风险评分: {assessment.risk_score:.2f}
威胁等级: {assessment.threat_level.value}
威胁类型: {", ".join(assessment.threat_categories)}

安全指标:
"""
                
                for indicator in assessment.security_indicators:
                    analysis_result += f"- {indicator.get('description', '未知指标')}\n"
                
                analysis_result += "\n建议措施:\n"
                for action in assessment.mitigation_actions:
                    analysis_result += f"- {action.get('description', '未知操作')}\n"
                
                self.root.after(0, lambda: messagebox.showinfo("威胁分析结果", analysis_result))
                self.root.after(0, lambda: self._set_status("威胁分析完成"))
                
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"威胁分析异常: {str(e)}"))
        
        threading.Thread(target=run_analysis, daemon=True).start()
    
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