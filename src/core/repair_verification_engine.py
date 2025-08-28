#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复验证机制和回滚功能模块
提供修复操作的验证、回滚和恢复功能
"""

import json
import os
import shutil
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field

from ..models import RepairResult, RepairStatus
from ..utils.logger import LoggerMixin
from .device_manager import DeviceManager


@dataclass
class BackupInfo:
    """备份信息"""
    backup_id: str
    original_path: str
    backup_path: str
    backup_time: datetime
    operation_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """验证结果"""
    success: bool
    verification_type: str
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)


class RepairVerificationEngine(LoggerMixin):
    """修复验证引擎"""
    
    def __init__(self, device_manager: DeviceManager, backup_dir: str = "/tmp/android_security_backups"):
        self.device_manager = device_manager
        self.backup_dir = backup_dir
        self.backups: Dict[str, BackupInfo] = {}
        self.verification_methods = {
            'permission_fix': self._verify_permission_fix,
            'config_fix': self._verify_config_fix,
            'system_fix': self._verify_system_fix,
            'app_fix': self._verify_app_fix
        }
        self._ensure_backup_directory()
    
    def _ensure_backup_directory(self):
        """确保备份目录存在"""
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
        except Exception as e:
            self.logger.error(f"创建备份目录失败: {e}")
    
    def create_backup(self, device_id: str, target_path: str, operation_type: str) -> Optional[str]:
        """创建备份"""
        try:
            backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(target_path) % 10000}"
            backup_path = os.path.join(self.backup_dir, f"{backup_id}.backup")
            
            # 从设备拉取文件
            result = self.device_manager.execute_command(device_id, f"cat {target_path}")
            if result:
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(result)
                
                backup_info = BackupInfo(
                    backup_id=backup_id,
                    original_path=target_path,
                    backup_path=backup_path,
                    backup_time=datetime.now(),
                    operation_type=operation_type,
                    metadata={'device_id': device_id, 'file_size': len(result)}
                )
                
                self.backups[backup_id] = backup_info
                self.logger.info(f"备份创建成功: {backup_id}")
                return backup_id
                
        except Exception as e:
            self.logger.error(f"创建备份失败: {e}")
        
        return None
    
    def verify_repair(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """验证修复结果"""
        try:
            repair_type = repair_result.repair_type
            verification_method = self.verification_methods.get(repair_type, self._default_verification)
            
            return verification_method(device_id, repair_result)
            
        except Exception as e:
            self.logger.error(f"修复验证失败: {e}")
            return VerificationResult(
                success=False,
                verification_type=repair_result.repair_type,
                details={'error': str(e)}
            )
    
    def _verify_permission_fix(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """验证权限修复"""
        try:
            target_path = repair_result.target_path
            expected_permissions = repair_result.target_value
            
            # 检查文件权限
            result = self.device_manager.execute_command(device_id, f"ls -l {target_path}")
            
            if result and expected_permissions in result:
                return VerificationResult(
                    success=True,
                    verification_type='permission_fix',
                    details={'current_permissions': result.strip(), 'expected': expected_permissions}
                )
            else:
                return VerificationResult(
                    success=False,
                    verification_type='permission_fix',
                    details={'current_permissions': result, 'expected': expected_permissions, 'error': '权限不匹配'}
                )
                
        except Exception as e:
            return VerificationResult(
                success=False,
                verification_type='permission_fix',
                details={'error': str(e)}
            )
    
    def _verify_config_fix(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """验证配置修复"""
        try:
            target_path = repair_result.target_path
            expected_value = repair_result.target_value
            
            # 检查配置文件内容
            result = self.device_manager.execute_command(device_id, f"cat {target_path}")
            
            if result and expected_value in result:
                return VerificationResult(
                    success=True,
                    verification_type='config_fix',
                    details={'config_verified': True, 'target_value': expected_value}
                )
            else:
                return VerificationResult(
                    success=False,
                    verification_type='config_fix',
                    details={'config_verified': False, 'current_content': result[:200], 'expected': expected_value}
                )
                
        except Exception as e:
            return VerificationResult(
                success=False,
                verification_type='config_fix',
                details={'error': str(e)}
            )
    
    def _verify_system_fix(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """验证系统修复"""
        try:
            # 检查系统服务状态
            service_name = repair_result.details.get('service_name', 'unknown')
            result = self.device_manager.execute_command(device_id, f"getprop init.svc.{service_name}")
            
            if result and 'running' in result:
                return VerificationResult(
                    success=True,
                    verification_type='system_fix',
                    details={'service_status': result.strip(), 'service_name': service_name}
                )
            else:
                return VerificationResult(
                    success=False,
                    verification_type='system_fix',
                    details={'service_status': result, 'service_name': service_name, 'error': '服务未运行'}
                )
                
        except Exception as e:
            return VerificationResult(
                success=False,
                verification_type='system_fix',
                details={'error': str(e)}
            )
    
    def _verify_app_fix(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """验证应用修复"""
        try:
            app_package = repair_result.details.get('package_name', 'unknown')
            
            # 检查应用状态
            result = self.device_manager.execute_command(device_id, f"dumpsys package {app_package}")
            
            if result and 'INSTALLED' in result:
                return VerificationResult(
                    success=True,
                    verification_type='app_fix',
                    details={'app_status': 'installed', 'package_name': app_package}
                )
            else:
                return VerificationResult(
                    success=False,
                    verification_type='app_fix',
                    details={'app_status': 'not_found', 'package_name': app_package}
                )
                
        except Exception as e:
            return VerificationResult(
                success=False,
                verification_type='app_fix',
                details={'error': str(e)}
            )
    
    def _default_verification(self, device_id: str, repair_result: RepairResult) -> VerificationResult:
        """默认验证方法"""
        return VerificationResult(
            success=True,
            verification_type='default',
            details={'message': '使用默认验证方法', 'repair_id': repair_result.repair_id}
        )


class RepairRollbackEngine(LoggerMixin):
    """修复回滚引擎"""
    
    def __init__(self, device_manager: DeviceManager, verification_engine: RepairVerificationEngine):
        self.device_manager = device_manager
        self.verification_engine = verification_engine
        self.rollback_history: List[Dict[str, Any]] = []
    
    def rollback_repair(self, device_id: str, backup_id: str) -> bool:
        """回滚修复操作"""
        try:
            backup_info = self.verification_engine.backups.get(backup_id)
            if not backup_info:
                self.logger.error(f"备份信息不存在: {backup_id}")
                return False
            
            # 读取备份内容
            with open(backup_info.backup_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            
            # 恢复文件
            success = self._restore_file(device_id, backup_info.original_path, backup_content)
            
            if success:
                rollback_record = {
                    'backup_id': backup_id,
                    'device_id': device_id,
                    'original_path': backup_info.original_path,
                    'rollback_time': datetime.now(),
                    'success': True
                }
                self.rollback_history.append(rollback_record)
                self.logger.info(f"回滚成功: {backup_id}")
                return True
            else:
                self.logger.error(f"回滚失败: {backup_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"回滚操作失败: {e}")
            return False
    
    def _restore_file(self, device_id: str, target_path: str, content: str) -> bool:
        """恢复文件"""
        try:
            # 创建临时文件
            temp_file = f"/tmp/restore_{hash(target_path) % 10000}.tmp"
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 推送到设备
            result = self.device_manager.execute_command(device_id, f"cp {temp_file} {target_path}")
            
            # 清理临时文件
            try:
                os.remove(temp_file)
            except:
                pass
            
            return result is not None
            
        except Exception as e:
            self.logger.error(f"文件恢复失败: {e}")
            return False
    
    def get_rollback_history(self) -> List[Dict[str, Any]]:
        """获取回滚历史"""
        return self.rollback_history.copy()


class RepairRecoveryManager(LoggerMixin):
    """修复恢复管理器"""
    
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
        self.verification_engine = RepairVerificationEngine(device_manager)
        self.rollback_engine = RepairRollbackEngine(device_manager, self.verification_engine)
        
    def safe_repair_with_verification(self, device_id: str, repair_operation: callable, 
                                    operation_type: str, target_path: str, **kwargs) -> Dict[str, Any]:
        """安全修复操作（带验证和回滚）"""
        try:
            # 创建备份
            backup_id = self.verification_engine.create_backup(device_id, target_path, operation_type)
            
            if not backup_id:
                return {'success': False, 'error': '备份创建失败'}
            
            try:
                # 执行修复操作
                repair_result = repair_operation(device_id, **kwargs)
                
                # 验证修复结果
                verification = self.verification_engine.verify_repair(device_id, repair_result)
                
                if verification.success:
                    return {
                        'success': True,
                        'repair_result': repair_result,
                        'verification': verification,
                        'backup_id': backup_id
                    }
                else:
                    # 验证失败，自动回滚
                    rollback_success = self.rollback_engine.rollback_repair(device_id, backup_id)
                    return {
                        'success': False,
                        'error': '修复验证失败',
                        'verification': verification,
                        'rollback_success': rollback_success,
                        'backup_id': backup_id
                    }
                    
            except Exception as repair_error:
                # 修复操作失败，尝试回滚
                rollback_success = self.rollback_engine.rollback_repair(device_id, backup_id)
                return {
                    'success': False,
                    'error': f'修复操作失败: {str(repair_error)}',
                    'rollback_success': rollback_success,
                    'backup_id': backup_id
                }
                
        except Exception as e:
            self.logger.error(f"安全修复操作失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def manual_rollback(self, device_id: str, backup_id: str) -> Dict[str, Any]:
        """手动回滚操作"""
        try:
            success = self.rollback_engine.rollback_repair(device_id, backup_id)
            return {
                'success': success,
                'backup_id': backup_id,
                'rollback_time': datetime.now()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_available_backups(self) -> List[Dict[str, Any]]:
        """列出可用的备份"""
        backups = []
        for backup_id, backup_info in self.verification_engine.backups.items():
            backups.append({
                'backup_id': backup_id,
                'original_path': backup_info.original_path,
                'backup_time': backup_info.backup_time.isoformat(),
                'operation_type': backup_info.operation_type,
                'metadata': backup_info.metadata
            })
        return backups
    
    def cleanup_old_backups(self, days_to_keep: int = 30):
        """清理旧备份"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days_to_keep)
            
            to_remove = []
            for backup_id, backup_info in self.verification_engine.backups.items():
                if backup_info.backup_time < cutoff_time:
                    to_remove.append(backup_id)
            
            for backup_id in to_remove:
                backup_info = self.verification_engine.backups[backup_id]
                try:
                    os.remove(backup_info.backup_path)
                except:
                    pass
                del self.verification_engine.backups[backup_id]
            
            self.logger.info(f"清理了 {len(to_remove)} 个旧备份")
            
        except Exception as e:
            self.logger.error(f"清理备份失败: {e}")