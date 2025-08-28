"""
模块化诊断工具
独立运行的系统诊断工具集合
"""

import sys
import os
import json
import argparse
import time
import subprocess
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from .logger import setup_logger
from .exception_handler import safe_execute


class DiagnosticStatus(Enum):
    """诊断状态"""
    PASS = "pass"
    WARNING = "warning" 
    FAIL = "fail"
    ERROR = "error"


@dataclass
class DiagnosticResult:
    """诊断结果"""
    checker_name: str
    status: DiagnosticStatus
    message: str
    details: Dict[str, Any]
    suggestions: List[str]
    duration: float


class BaseDiagnostic(ABC):
    """诊断工具基类"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(f"Diagnostic.{name}")
    
    @abstractmethod
    def check(self) -> DiagnosticResult:
        """执行诊断检查"""
        pass
    
    def run_standalone(self, output_format: str = "json") -> Dict[str, Any]:
        """独立运行模式"""
        start_time = time.time()
        
        try:
            result = self.check()
            result.duration = time.time() - start_time
            
            output = {
                "checker": self.name,
                "timestamp": time.time(),
                "result": {
                    "status": result.status.value,
                    "message": result.message,
                    "details": result.details,
                    "suggestions": result.suggestions,
                    "duration": result.duration
                }
            }
            
            if output_format == "json":
                print(json.dumps(output, indent=2, ensure_ascii=False))
            else:
                self._print_text_output(output)
            
            return output
            
        except Exception as e:
            self.logger.error(f"诊断执行失败: {e}")
            error_output = {
                "checker": self.name,
                "timestamp": time.time(),
                "error": str(e),
                "duration": time.time() - start_time
            }
            
            if output_format == "json":
                print(json.dumps(error_output, indent=2, ensure_ascii=False))
            else:
                print(f"❌ 诊断失败: {e}")
            
            return error_output
    
    def _print_text_output(self, output: Dict[str, Any]):
        """打印文本格式输出"""
        result = output.get("result", {})
        status = result.get("status", "error")
        
        # 状态图标
        status_icons = {
            "pass": "✅",
            "warning": "⚠️", 
            "fail": "❌",
            "error": "💥"
        }
        
        icon = status_icons.get(status, "❓")
        
        print(f"\n{icon} {self.name} 诊断报告")
        print("=" * 50)
        print(f"状态: {status.upper()}")
        print(f"消息: {result.get('message', 'N/A')}")
        print(f"耗时: {result.get('duration', 0):.2f}秒")
        
        # 详细信息
        details = result.get("details", {})
        if details:
            print("\n详细信息:")
            for key, value in details.items():
                print(f"  {key}: {value}")
        
        # 建议
        suggestions = result.get("suggestions", [])
        if suggestions:
            print("\n建议:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"  {i}. {suggestion}")


class PythonEnvironmentDiagnostic(BaseDiagnostic):
    """Python环境诊断"""
    
    def __init__(self):
        super().__init__("Python环境检查")
    
    def check(self) -> DiagnosticResult:
        issues = []
        warnings = []
        details = {}
        suggestions = []
        
        # 检查Python版本
        version = sys.version_info
        details["python_version"] = f"{version.major}.{version.minor}.{version.micro}"
        
        if version < (3, 8):
            issues.append(f"Python版本过低: {details['python_version']}")
            suggestions.append("升级Python到3.8或更高版本")
        elif version < (3, 9):
            warnings.append("建议使用Python 3.9+以获得更好的性能")
        
        # 检查pip
        try:
            import pip
            details["pip_version"] = pip.__version__
        except ImportError:
            issues.append("pip未安装")
            suggestions.append("安装pip包管理器")
        
        # 检查虚拟环境
        in_venv = sys.prefix != sys.base_prefix
        details["virtual_environment"] = in_venv
        if not in_venv:
            warnings.append("未使用虚拟环境")
            suggestions.append("建议使用虚拟环境隔离依赖")
        
        # 确定状态
        if issues:
            status = DiagnosticStatus.FAIL
            message = f"发现 {len(issues)} 个问题"
        elif warnings:
            status = DiagnosticStatus.WARNING
            message = f"发现 {len(warnings)} 个警告"
        else:
            status = DiagnosticStatus.PASS
            message = "Python环境正常"
        
        return DiagnosticResult(
            checker_name=self.name,
            status=status,
            message=message,
            details=details,
            suggestions=suggestions,
            duration=0
        )


class SystemResourceDiagnostic(BaseDiagnostic):
    """系统资源诊断"""
    
    def __init__(self):
        super().__init__("系统资源检查")
    
    def check(self) -> DiagnosticResult:
        issues = []
        warnings = []
        details = {}
        suggestions = []
        
        try:
            import psutil
            
            # 内存检查
            memory = psutil.virtual_memory()
            details["memory_total"] = f"{memory.total / 1024**3:.1f} GB"
            details["memory_available"] = f"{memory.available / 1024**3:.1f} GB"
            details["memory_percent"] = memory.percent
            
            if memory.percent > 90:
                issues.append("内存使用率过高")
                suggestions.append("关闭不必要的程序释放内存")
            elif memory.percent > 80:
                warnings.append("内存使用率较高")
            
            # 磁盘检查
            disk = psutil.disk_usage('.')
            details["disk_total"] = f"{disk.total / 1024**3:.1f} GB"
            details["disk_free"] = f"{disk.free / 1024**3:.1f} GB" 
            details["disk_percent"] = (disk.used / disk.total) * 100
            
            if disk.free < 1024**3:  # 小于1GB
                issues.append("磁盘空间不足")
                suggestions.append("清理磁盘空间")
            elif disk.free < 5 * 1024**3:  # 小于5GB
                warnings.append("磁盘空间较少")
            
            # CPU检查
            cpu_percent = psutil.cpu_percent(interval=1)
            details["cpu_percent"] = cpu_percent
            details["cpu_count"] = psutil.cpu_count()
            
            if cpu_percent > 90:
                warnings.append("CPU使用率很高")
            
        except ImportError:
            issues.append("psutil库未安装，无法检查系统资源")
            suggestions.append("安装psutil库: pip install psutil")
        except Exception as e:
            issues.append(f"系统资源检查失败: {e}")
        
        # 确定状态
        if issues:
            status = DiagnosticStatus.FAIL
            message = f"发现 {len(issues)} 个问题"
        elif warnings:
            status = DiagnosticStatus.WARNING
            message = f"发现 {len(warnings)} 个警告"
        else:
            status = DiagnosticStatus.PASS
            message = "系统资源充足"
        
        return DiagnosticResult(
            checker_name=self.name,
            status=status,
            message=message,
            details=details,
            suggestions=suggestions,
            duration=0
        )


class NetworkConnectivityDiagnostic(BaseDiagnostic):
    """网络连接诊断"""
    
    def __init__(self):
        super().__init__("网络连接检查")
    
    def check(self) -> DiagnosticResult:
        issues = []
        warnings = []
        details = {}
        suggestions = []
        
        # 测试目标
        test_hosts = [
            ("谷歌DNS", "8.8.8.8"),
            ("百度", "www.baidu.com"),
            ("GitHub", "github.com")
        ]
        
        connectivity_results = {}
        
        for name, host in test_hosts:
            try:
                if self._test_connectivity(host):
                    connectivity_results[name] = "可达"
                else:
                    connectivity_results[name] = "不可达"
                    issues.append(f"无法连接到 {name} ({host})")
            except Exception as e:
                connectivity_results[name] = f"测试失败: {e}"
                warnings.append(f"{name} 连接测试异常")
        
        details["connectivity"] = connectivity_results
        
        # 检查代理设置
        proxy_info = self._check_proxy()
        details["proxy"] = proxy_info
        
        # 确定状态
        failed_connections = len([v for v in connectivity_results.values() if v == "不可达"])
        
        if failed_connections >= len(test_hosts):
            status = DiagnosticStatus.FAIL
            message = "网络完全不可用"
            suggestions.append("检查网络连接和防火墙设置")
        elif failed_connections > 0:
            status = DiagnosticStatus.WARNING
            message = f"部分网络连接失败 ({failed_connections}/{len(test_hosts)})"
            suggestions.append("检查特定网站的访问权限")
        else:
            status = DiagnosticStatus.PASS
            message = "网络连接正常"
        
        return DiagnosticResult(
            checker_name=self.name,
            status=status,
            message=message,
            details=details,
            suggestions=suggestions,
            duration=0
        )
    
    def _test_connectivity(self, host: str, timeout: int = 5) -> bool:
        """测试网络连接"""
        try:
            import socket
            
            if host.replace('.', '').isdigit():  # IP地址
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, 53))  # DNS端口
                sock.close()
                return result == 0
            else:  # 域名
                socket.setdefaulttimeout(timeout)
                socket.gethostbyname(host)
                return True
        except:
            return False
    
    def _check_proxy(self) -> Dict[str, str]:
        """检查代理设置"""
        proxy_info = {}
        
        # 检查环境变量
        proxy_vars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]
        for var in proxy_vars:
            value = os.environ.get(var)
            if value:
                proxy_info[var] = value
        
        if not proxy_info:
            proxy_info["status"] = "未设置代理"
        
        return proxy_info


class DiagnosticRunner:
    """诊断运行器"""
    
    def __init__(self):
        self.logger = setup_logger("DiagnosticRunner")
        self.diagnostics: Dict[str, BaseDiagnostic] = {}
        
        # 注册默认诊断工具
        self._register_default_diagnostics()
    
    def register_diagnostic(self, key: str, diagnostic: BaseDiagnostic):
        """注册诊断工具"""
        self.diagnostics[key] = diagnostic
        self.logger.info(f"注册诊断工具: {key}")
    
    def run_all(self, output_format: str = "json") -> Dict[str, Any]:
        """运行所有诊断"""
        results = {
            "timestamp": time.time(),
            "diagnostics": {},
            "summary": {
                "total": len(self.diagnostics),
                "passed": 0,
                "warnings": 0,
                "failed": 0,
                "errors": 0
            }
        }
        
        for key, diagnostic in self.diagnostics.items():
            try:
                start_time = time.time()
                result = diagnostic.check()
                result.duration = time.time() - start_time
                
                results["diagnostics"][key] = {
                    "status": result.status.value,
                    "message": result.message,
                    "details": result.details,
                    "suggestions": result.suggestions,
                    "duration": result.duration
                }
                
                # 更新统计
                if result.status == DiagnosticStatus.PASS:
                    results["summary"]["passed"] += 1
                elif result.status == DiagnosticStatus.WARNING:
                    results["summary"]["warnings"] += 1
                elif result.status == DiagnosticStatus.FAIL:
                    results["summary"]["failed"] += 1
                else:
                    results["summary"]["errors"] += 1
                
            except Exception as e:
                self.logger.error(f"诊断 {key} 执行失败: {e}")
                results["diagnostics"][key] = {
                    "status": "error",
                    "message": f"执行失败: {e}",
                    "details": {},
                    "suggestions": [],
                    "duration": 0
                }
                results["summary"]["errors"] += 1
        
        if output_format == "json":
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            self._print_summary_text(results)
        
        return results
    
    def run_specific(self, diagnostic_names: List[str], output_format: str = "json") -> Dict[str, Any]:
        """运行特定诊断"""
        available_diagnostics = {k: v for k, v in self.diagnostics.items() if k in diagnostic_names}
        
        if not available_diagnostics:
            error_msg = f"未找到指定的诊断工具: {diagnostic_names}"
            self.logger.error(error_msg)
            return {"error": error_msg}
        
        # 临时替换诊断工具列表
        original_diagnostics = self.diagnostics
        self.diagnostics = available_diagnostics
        
        try:
            return self.run_all(output_format)
        finally:
            self.diagnostics = original_diagnostics
    
    def _register_default_diagnostics(self):
        """注册默认诊断工具"""
        self.register_diagnostic("python", PythonEnvironmentDiagnostic())
        self.register_diagnostic("system", SystemResourceDiagnostic())
        self.register_diagnostic("network", NetworkConnectivityDiagnostic())
    
    def _print_summary_text(self, results: Dict[str, Any]):
        """打印文本格式摘要"""
        summary = results["summary"]
        
        print("\n" + "=" * 60)
        print("🔍 诊断摘要报告")
        print("=" * 60)
        
        print(f"总数: {summary['total']}")
        print(f"✅ 通过: {summary['passed']}")
        print(f"⚠️ 警告: {summary['warnings']}")
        print(f"❌ 失败: {summary['failed']}")
        print(f"💥 错误: {summary['errors']}")
        
        print("\n详细结果:")
        for name, result in results["diagnostics"].items():
            status_icons = {
                "pass": "✅",
                "warning": "⚠️", 
                "fail": "❌",
                "error": "💥"
            }
            
            icon = status_icons.get(result["status"], "❓")
            print(f"{icon} {name}: {result['message']}")


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(description="模块化诊断工具")
    
    parser.add_argument("--diagnostic", "-d",
                       choices=["python", "system", "network", "all"],
                       default="all",
                       help="要运行的诊断工具")
    
    parser.add_argument("--format", "-f",
                       choices=["json", "text"],
                       default="text",
                       help="输出格式")
    
    parser.add_argument("--list", "-l",
                       action="store_true",
                       help="列出可用的诊断工具")
    
    args = parser.parse_args()
    
    runner = DiagnosticRunner()
    
    if args.list:
        print("可用的诊断工具:")
        for key in runner.diagnostics.keys():
            print(f"  - {key}")
        return
    
    if args.diagnostic == "all":
        runner.run_all(args.format)
    else:
        runner.run_specific([args.diagnostic], args.format)


if __name__ == "__main__":
    main()