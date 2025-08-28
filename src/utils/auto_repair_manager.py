"""
自动修复管理器
实现问题自动检测和修复功能
"""

import sys
import os
import threading
import time
from typing import Dict, List, Any, Optional, Callable, Type, Union
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from .logger import setup_logger
from .exception_handler import get_exception_center, ExceptionSeverity


class ProblemType(Enum):
    """问题类型"""
    DEPENDENCY_MISSING = "dependency_missing"
    CONFIG_INVALID = "config_invalid"  
    ENVIRONMENT_ERROR = "environment_error"
    PERMISSION_DENIED = "permission_denied"
    DISK_SPACE_LOW = "disk_space_low"
    MEMORY_INSUFFICIENT = "memory_insufficient"
    NETWORK_UNAVAILABLE = "network_unavailable"
    FILE_CORRUPTED = "file_corrupted"


class RepairStatus(Enum):
    """修复状态"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Problem:
    """问题定义"""
    problem_type: ProblemType
    severity: int  # 1-10, 10最严重
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    auto_fixable: bool = True
    fix_priority: int = 5  # 1-10, 10最优先


@dataclass
class RepairTask:
    """修复任务"""
    task_id: str
    problem: Problem
    repairer_class: str
    status: RepairStatus = RepairStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class BaseRepairer(ABC):
    """修复器基类"""
    
    def __init__(self):
        self.logger = setup_logger(self.__class__.__name__)
    
    @abstractmethod
    def can_repair(self, problem: Problem) -> bool:
        """判断是否可以修复该问题"""
        pass
    
    @abstractmethod
    def estimate_time(self, problem: Problem) -> int:
        """估算修复时间（秒）"""
        pass
    
    @abstractmethod
    def execute(self, problem: Problem) -> Dict[str, Any]:
        """执行修复"""
        pass
    
    def rollback(self, problem: Problem, repair_result: Dict[str, Any]) -> bool:
        """回滚修复操作（可选实现）"""
        return False


class DependencyRepairer(BaseRepairer):
    """依赖修复器"""
    
    def can_repair(self, problem: Problem) -> bool:
        return problem.problem_type == ProblemType.DEPENDENCY_MISSING
    
    def estimate_time(self, problem: Problem) -> int:
        return 30  # 预估30秒
    
    def execute(self, problem: Problem) -> Dict[str, Any]:
        try:
            missing_packages = problem.details.get("missing_packages", [])
            installed = []
            failed = []
            
            import subprocess
            for package in missing_packages:
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", package],
                        capture_output=True, text=True, timeout=60
                    )
                    if result.returncode == 0:
                        installed.append(package)
                        self.logger.info(f"成功安装: {package}")
                    else:
                        failed.append(package)
                        self.logger.error(f"安装失败: {package}")
                except Exception as e:
                    failed.append(package)
                    self.logger.error(f"安装异常 {package}: {e}")
            
            success = len(failed) == 0
            return {
                "success": success,
                "installed": installed,
                "failed": failed,
                "message": f"已安装 {len(installed)} 个包，{len(failed)} 个失败"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


class ConfigRepairer(BaseRepairer):
    """配置修复器"""
    
    def can_repair(self, problem: Problem) -> bool:
        return problem.problem_type == ProblemType.CONFIG_INVALID
    
    def estimate_time(self, problem: Problem) -> int:
        return 5
    
    def execute(self, problem: Problem) -> Dict[str, Any]:
        try:
            config_path = problem.details.get("config_path", "config.ini")
            
            # 创建备份
            if os.path.exists(config_path):
                backup_path = f"{config_path}.backup.{int(time.time())}"
                import shutil
                shutil.copy2(config_path, backup_path)
                self.logger.info(f"配置文件已备份到: {backup_path}")
            
            # 创建默认配置
            from .config_validator import ConfigValidator
            validator = ConfigValidator()
            default_config = validator.create_default_config()
            
            with open(config_path, 'w', encoding='utf-8') as f:
                default_config.write(f)
            
            return {
                "success": True,
                "message": f"已修复配置文件: {config_path}",
                "backup_created": os.path.exists(backup_path) if 'backup_path' in locals() else False
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


class AutoRepairManager:
    """自动修复管理器"""
    
    def __init__(self):
        self.logger = setup_logger("AutoRepairManager")
        self.repairers: Dict[ProblemType, List[BaseRepairer]] = {}
        self.repair_tasks: Dict[str, RepairTask] = {}
        self.repair_history: List[RepairTask] = []
        self.lock = threading.RLock()
        
        # 注册默认修复器
        self._register_default_repairers()
    
    def register_repairer(self, problem_type: ProblemType, repairer: BaseRepairer):
        """注册修复器"""
        with self.lock:
            if problem_type not in self.repairers:
                self.repairers[problem_type] = []
            self.repairers[problem_type].append(repairer)
        
        self.logger.info(f"注册修复器: {repairer.__class__.__name__} -> {problem_type.value}")
    
    def diagnose_and_repair(self, problems: List[Problem]) -> Dict[str, Any]:
        """诊断并修复问题"""
        if not problems:
            return {"success": True, "message": "无问题需要修复"}
        
        # 创建修复计划
        repair_plan = self.create_repair_plan(problems)
        
        # 执行修复计划
        return self.execute_repair_plan(repair_plan)
    
    def create_repair_plan(self, problems: List[Problem]) -> List[RepairTask]:
        """创建修复计划"""
        tasks = []
        
        # 按优先级和严重程度排序
        sorted_problems = sorted(problems, 
                               key=lambda p: (p.fix_priority, p.severity), 
                               reverse=True)
        
        for problem in sorted_problems:
            if not problem.auto_fixable:
                self.logger.info(f"跳过非自动修复问题: {problem.description}")
                continue
            
            # 查找合适的修复器
            repairer = self._find_repairer(problem)
            if repairer:
                task_id = f"repair_{int(time.time() * 1000)}_{len(tasks)}"
                task = RepairTask(
                    task_id=task_id,
                    problem=problem,
                    repairer_class=repairer.__class__.__name__
                )
                tasks.append(task)
                
                with self.lock:
                    self.repair_tasks[task_id] = task
            else:
                self.logger.warning(f"未找到修复器: {problem.description}")
        
        return tasks
    
    def execute_repair_plan(self, repair_plan: List[RepairTask]) -> Dict[str, Any]:
        """执行修复计划"""
        results = {
            "total_tasks": len(repair_plan),
            "successful": 0,
            "failed": 0,
            "skipped": 0,
            "details": []
        }
        
        for task in repair_plan:
            try:
                task.status = RepairStatus.IN_PROGRESS
                task.start_time = time.time()
                
                # 执行修复
                repairer = self._get_repairer_instance(task.repairer_class, task.problem.problem_type)
                if repairer:
                    repair_result = repairer.execute(task.problem)
                    task.result = repair_result
                    
                    if repair_result.get("success", False):
                        task.status = RepairStatus.SUCCESS
                        results["successful"] += 1
                        self.logger.info(f"修复成功: {task.problem.description}")
                    else:
                        task.status = RepairStatus.FAILED
                        task.error_message = repair_result.get("error", "未知错误")
                        results["failed"] += 1
                        self.logger.error(f"修复失败: {task.problem.description}")
                else:
                    task.status = RepairStatus.SKIPPED
                    task.error_message = "未找到修复器"
                    results["skipped"] += 1
                
                task.end_time = time.time()
                
                # 添加到结果详情
                results["details"].append({
                    "task_id": task.task_id,
                    "problem": task.problem.description,
                    "status": task.status.value,
                    "duration": task.end_time - task.start_time,
                    "result": task.result
                })
                
            except Exception as e:
                task.status = RepairStatus.FAILED
                task.error_message = str(e)
                task.end_time = time.time()
                results["failed"] += 1
                
                self.logger.error(f"修复任务异常: {task.problem.description}, {e}")
                get_exception_center().handle_exception(e)
            
            finally:
                # 保存到历史记录
                with self.lock:
                    self.repair_history.append(task)
        
        results["success_rate"] = results["successful"] / results["total_tasks"] * 100 if results["total_tasks"] > 0 else 0
        
        self.logger.info(f"修复计划执行完成: {results['successful']}/{results['total_tasks']} 成功")
        return results
    
    def _register_default_repairers(self):
        """注册默认修复器"""
        self.register_repairer(ProblemType.DEPENDENCY_MISSING, DependencyRepairer())
        self.register_repairer(ProblemType.CONFIG_INVALID, ConfigRepairer())
    
    def _find_repairer(self, problem: Problem) -> Optional[BaseRepairer]:
        """查找合适的修复器"""
        repairers = self.repairers.get(problem.problem_type, [])
        for repairer in repairers:
            if repairer.can_repair(problem):
                return repairer
        return None
    
    def _get_repairer_instance(self, repairer_class_name: str, problem_type: ProblemType) -> Optional[BaseRepairer]:
        """获取修复器实例"""
        repairers = self.repairers.get(problem_type, [])
        for repairer in repairers:
            if repairer.__class__.__name__ == repairer_class_name:
                return repairer
        return None


# 全局自动修复管理器
_global_repair_manager = None
_manager_lock = threading.Lock()


def get_auto_repair_manager() -> AutoRepairManager:
    """获取全局自动修复管理器实例"""
    global _global_repair_manager
    if _global_repair_manager is None:
        with _manager_lock:
            if _global_repair_manager is None:
                _global_repair_manager = AutoRepairManager()
    return _global_repair_manager