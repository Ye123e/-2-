#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
隔离管理器 - 恶意应用隔离、安全删除和恢复机制
"""

import os
import json
import time
import shutil
import hashlib
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..utils.logger import LoggerMixin


class QuarantineStatus(Enum):
    """隔离状态"""
    QUARANTINED = "QUARANTINED"      # 已隔离
    RESTORED = "RESTORED"            # 已恢复
    DELETED = "DELETED"              # 已删除
    EXPIRED = "EXPIRED"              # 已过期


class QuarantineReason(Enum):
    """隔离原因"""
    VIRUS_DETECTION = "VIRUS_DETECTION"        # 病毒检测
    MALWARE_ANALYSIS = "MALWARE_ANALYSIS"      # 恶意软件分析
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR" # 可疑行为
    USER_REQUEST = "USER_REQUEST"              # 用户请求
    POLICY_VIOLATION = "POLICY_VIOLATION"      # 策略违规


@dataclass
class QuarantineItem:
    """隔离项目"""
    item_id: str
    original_path: str
    package_name: str
    quarantine_path: str
    reason: QuarantineReason
    status: QuarantineStatus
    quarantine_time: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    file_hash: str = ""
    file_size: int = 0
    restoration_info: Optional[Dict[str, Any]] = None


class QuarantineManager(LoggerMixin):
    """隔离管理器"""
    
    def __init__(self, quarantine_base_path: str = "data/quarantine"):
        self.quarantine_base_path = Path(quarantine_base_path)
        self.quarantine_base_path.mkdir(parents=True, exist_ok=True)
        
        # 隔离配置
        self.config = {
            'max_quarantine_size_gb': 5,      # 最大隔离区大小(GB)
            'auto_cleanup_days': 30,          # 自动清理天数
            'encrypt_quarantine': True,       # 是否加密隔离文件
            'compress_files': True,           # 是否压缩文件
            'log_quarantine_actions': True,   # 是否记录隔离操作
            'allow_restoration': True,        # 是否允许恢复
            'require_admin_approval': False   # 是否需要管理员批准
        }
        
        # 隔离索引文件
        self.index_file = self.quarantine_base_path / "quarantine_index.json"
        self.quarantine_items: Dict[str, QuarantineItem] = {}
        
        # 加载现有隔离项目
        self._load_quarantine_index()
        
        # 创建隔离目录结构
        self._init_quarantine_structure()
    
    def _init_quarantine_structure(self):
        """初始化隔离目录结构"""
        directories = [
            "files",        # 隔离文件存储
            "apps",         # 隔离应用存储
            "metadata",     # 元数据存储
            "logs",         # 隔离日志
            "temp"          # 临时文件
        ]
        
        for directory in directories:
            (self.quarantine_base_path / directory).mkdir(exist_ok=True)
    
    def _load_quarantine_index(self):
        """加载隔离索引"""
        try:
            if self.index_file.exists():
                with open(self.index_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for item_data in data.get('items', []):
                    item = QuarantineItem(
                        item_id=item_data['item_id'],
                        original_path=item_data['original_path'],
                        package_name=item_data['package_name'],
                        quarantine_path=item_data['quarantine_path'],
                        reason=QuarantineReason(item_data['reason']),
                        status=QuarantineStatus(item_data['status']),
                        quarantine_time=datetime.fromisoformat(item_data['quarantine_time']),
                        metadata=item_data.get('metadata', {}),
                        file_hash=item_data.get('file_hash', ''),
                        file_size=item_data.get('file_size', 0),
                        restoration_info=item_data.get('restoration_info')
                    )
                    self.quarantine_items[item.item_id] = item
                
                self.logger.info(f"加载隔离索引: {len(self.quarantine_items)} 个项目")
        
        except Exception as e:
            self.logger.error(f"加载隔离索引失败: {e}")
    
    def _save_quarantine_index(self):
        """保存隔离索引"""
        try:
            data = {
                'version': '1.0',
                'updated': datetime.now().isoformat(),
                'total_items': len(self.quarantine_items),
                'items': []
            }
            
            for item in self.quarantine_items.values():
                item_data = {
                    'item_id': item.item_id,
                    'original_path': item.original_path,
                    'package_name': item.package_name,
                    'quarantine_path': item.quarantine_path,
                    'reason': item.reason.value,
                    'status': item.status.value,
                    'quarantine_time': item.quarantine_time.isoformat(),
                    'metadata': item.metadata,
                    'file_hash': item.file_hash,
                    'file_size': item.file_size,
                    'restoration_info': item.restoration_info
                }
                data['items'].append(item_data)
            
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            self.logger.error(f"保存隔离索引失败: {e}")
    
    def quarantine_file(self, file_path: str, package_name: str = "", 
                       reason: QuarantineReason = QuarantineReason.VIRUS_DETECTION,
                       metadata: Dict[str, Any] = None) -> Optional[str]:
        """隔离文件"""
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"文件不存在: {file_path}")
                return None
            
            # 生成隔离项目ID
            item_id = self._generate_item_id(file_path)
            
            # 计算文件哈希
            file_hash = self._calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # 检查隔离区空间
            if not self._check_quarantine_space(file_size):
                self.logger.error("隔离区空间不足")
                return None
            
            # 创建隔离路径
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{os.path.basename(file_path)}"
            quarantine_path = self.quarantine_base_path / "files" / quarantine_filename
            
            # 复制文件到隔离区
            if self.config['compress_files']:
                quarantine_path = self._compress_and_copy(file_path, quarantine_path)
            else:
                shutil.copy2(file_path, quarantine_path)
            
            # 加密文件（如果启用）
            if self.config['encrypt_quarantine']:
                quarantine_path = self._encrypt_file(quarantine_path)
            
            # 创建隔离项目
            quarantine_item = QuarantineItem(
                item_id=item_id,
                original_path=file_path,
                package_name=package_name,
                quarantine_path=str(quarantine_path),
                reason=reason,
                status=QuarantineStatus.QUARANTINED,
                quarantine_time=datetime.now(),
                metadata=metadata or {},
                file_hash=file_hash,
                file_size=file_size,
                restoration_info={
                    'original_permissions': oct(os.stat(file_path).st_mode)[-3:],
                    'original_owner': os.stat(file_path).st_uid,
                    'original_group': os.stat(file_path).st_gid
                }
            )
            
            # 添加到隔离列表
            self.quarantine_items[item_id] = quarantine_item
            
            # 保存索引
            self._save_quarantine_index()
            
            # 记录日志
            self._log_quarantine_action("QUARANTINE", quarantine_item)
            
            self.logger.info(f"文件已隔离: {file_path} -> {quarantine_path}")
            return item_id
        
        except Exception as e:
            self.logger.error(f"隔离文件失败: {e}")
            return None
    
    def quarantine_application(self, device_manager, device_id: str, package_name: str,
                             reason: QuarantineReason = QuarantineReason.MALWARE_ANALYSIS,
                             metadata: Dict[str, Any] = None) -> Optional[str]:
        """隔离应用程序"""
        try:
            # 获取APK路径
            apk_path = self._get_apk_path(device_manager, device_id, package_name)
            if not apk_path:
                self.logger.error(f"无法获取APK路径: {package_name}")
                return None
            
            # 生成隔离项目ID
            item_id = self._generate_item_id(package_name)
            
            # 创建隔离目录
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_dir = self.quarantine_base_path / "apps" / f"{timestamp}_{package_name}"
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            # 备份APK文件
            apk_backup_path = quarantine_dir / f"{package_name}.apk"
            apk_content = self._download_apk(device_manager, device_id, apk_path)
            if apk_content:
                with open(apk_backup_path, 'wb') as f:
                    f.write(apk_content)
            
            # 备份应用数据
            data_backup_path = quarantine_dir / "app_data"
            self._backup_app_data(device_manager, device_id, package_name, data_backup_path)
            
            # 禁用应用
            disable_success = self._disable_application(device_manager, device_id, package_name)
            
            # 创建隔离项目
            quarantine_item = QuarantineItem(
                item_id=item_id,
                original_path=apk_path,
                package_name=package_name,
                quarantine_path=str(quarantine_dir),
                reason=reason,
                status=QuarantineStatus.QUARANTINED,
                quarantine_time=datetime.now(),
                metadata=metadata or {},
                file_hash=self._calculate_content_hash(apk_content) if apk_content else "",
                file_size=len(apk_content) if apk_content else 0,
                restoration_info={
                    'apk_path': apk_path,
                    'disabled': disable_success,
                    'data_backed_up': data_backup_path.exists()
                }
            )
            
            # 添加到隔离列表
            self.quarantine_items[item_id] = quarantine_item
            
            # 保存索引
            self._save_quarantine_index()
            
            # 记录日志
            self._log_quarantine_action("QUARANTINE_APP", quarantine_item)
            
            self.logger.info(f"应用已隔离: {package_name}")
            return item_id
        
        except Exception as e:
            self.logger.error(f"隔离应用失败: {e}")
            return None
    
    def restore_item(self, item_id: str, device_manager=None, device_id: str = "") -> bool:
        """恢复隔离项目"""
        try:
            if item_id not in self.quarantine_items:
                self.logger.error(f"隔离项目不存在: {item_id}")
                return False
            
            item = self.quarantine_items[item_id]
            
            if item.status != QuarantineStatus.QUARANTINED:
                self.logger.error(f"项目状态不允许恢复: {item.status}")
                return False
            
            if not self.config['allow_restoration']:
                self.logger.error("系统不允许恢复隔离项目")
                return False
            
            # 检查原始路径是否存在
            if item.package_name and device_manager:
                # 恢复应用
                success = self._restore_application(device_manager, device_id, item)
            else:
                # 恢复文件
                success = self._restore_file(item)
            
            if success:
                item.status = QuarantineStatus.RESTORED
                self._save_quarantine_index()
                self._log_quarantine_action("RESTORE", item)
                self.logger.info(f"隔离项目已恢复: {item_id}")
                return True
            else:
                self.logger.error(f"恢复隔离项目失败: {item_id}")
                return False
        
        except Exception as e:
            self.logger.error(f"恢复隔离项目异常: {e}")
            return False
    
    def delete_item(self, item_id: str) -> bool:
        """永久删除隔离项目"""
        try:
            if item_id not in self.quarantine_items:
                self.logger.error(f"隔离项目不存在: {item_id}")
                return False
            
            item = self.quarantine_items[item_id]
            
            # 删除隔离文件
            quarantine_path = Path(item.quarantine_path)
            if quarantine_path.exists():
                if quarantine_path.is_dir():
                    shutil.rmtree(quarantine_path)
                else:
                    quarantine_path.unlink()
            
            # 更新状态
            item.status = QuarantineStatus.DELETED
            
            # 记录日志
            self._log_quarantine_action("DELETE", item)
            
            # 从列表中移除
            del self.quarantine_items[item_id]
            
            # 保存索引
            self._save_quarantine_index()
            
            self.logger.info(f"隔离项目已删除: {item_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"删除隔离项目失败: {e}")
            return False
    
    def cleanup_expired_items(self) -> int:
        """清理过期隔离项目"""
        try:
            expired_items = []
            expiry_date = datetime.now() - timedelta(days=self.config['auto_cleanup_days'])
            
            for item_id, item in self.quarantine_items.items():
                if item.quarantine_time < expiry_date and item.status == QuarantineStatus.QUARANTINED:
                    expired_items.append(item_id)
            
            cleanup_count = 0
            for item_id in expired_items:
                if self.delete_item(item_id):
                    cleanup_count += 1
            
            if cleanup_count > 0:
                self.logger.info(f"清理了 {cleanup_count} 个过期隔离项目")
            
            return cleanup_count
        
        except Exception as e:
            self.logger.error(f"清理过期项目失败: {e}")
            return 0
    
    def get_quarantine_items(self, status: Optional[QuarantineStatus] = None) -> List[QuarantineItem]:
        """获取隔离项目列表"""
        if status:
            return [item for item in self.quarantine_items.values() if item.status == status]
        return list(self.quarantine_items.values())
    
    def get_quarantine_statistics(self) -> Dict[str, Any]:
        """获取隔离统计信息"""
        total_items = len(self.quarantine_items)
        status_counts = {}
        total_size = 0
        
        for status in QuarantineStatus:
            status_counts[status.value] = sum(1 for item in self.quarantine_items.values() if item.status == status)
        
        for item in self.quarantine_items.values():
            total_size += item.file_size
        
        return {
            'total_items': total_items,
            'status_counts': status_counts,
            'total_size_mb': total_size / (1024 * 1024),
            'quarantine_path': str(self.quarantine_base_path),
            'auto_cleanup_days': self.config['auto_cleanup_days']
        }
    
    def _generate_item_id(self, identifier: str) -> str:
        """生成隔离项目ID"""
        timestamp = str(int(time.time()))
        return hashlib.md5(f"{identifier}_{timestamp}".encode()).hexdigest()[:16]
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件哈希"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""
    
    def _calculate_content_hash(self, content: bytes) -> str:
        """计算内容哈希"""
        return hashlib.sha256(content).hexdigest()
    
    def _check_quarantine_space(self, file_size: int) -> bool:
        """检查隔离区空间"""
        try:
            # 计算当前隔离区使用大小
            current_size = sum(item.file_size for item in self.quarantine_items.values()
                             if item.status == QuarantineStatus.QUARANTINED)
            
            max_size = self.config['max_quarantine_size_gb'] * 1024 * 1024 * 1024
            
            return (current_size + file_size) < max_size
        except:
            return True  # 默认允许
    
    def _compress_and_copy(self, source_path: str, dest_path: Path) -> Path:
        """压缩并复制文件"""
        import gzip
        
        compressed_path = dest_path.with_suffix(dest_path.suffix + '.gz')
        
        with open(source_path, 'rb') as f_in:
            with gzip.open(compressed_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return compressed_path
    
    def _encrypt_file(self, file_path: Path) -> Path:
        """加密文件（简单异或加密）"""
        # 这里实现简单的加密，实际项目中应使用更安全的加密方法
        encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
        
        key = b'quarantine_key_2023'  # 实际使用中应该是随机密钥
        
        with open(file_path, 'rb') as f_in:
            with open(encrypted_path, 'wb') as f_out:
                data = f_in.read()
                encrypted_data = bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
                f_out.write(encrypted_data)
        
        # 删除原文件
        file_path.unlink()
        
        return encrypted_path
    
    def _get_apk_path(self, device_manager, device_id: str, package_name: str) -> Optional[str]:
        """获取APK路径"""
        try:
            result = device_manager.adb_manager.execute_command(
                device_id, f"pm path {package_name}"
            )
            
            if result and 'package:' in result:
                return result.split('package:')[1].strip()
            
            return None
        except:
            return None
    
    def _download_apk(self, device_manager, device_id: str, apk_path: str) -> Optional[bytes]:
        """下载APK文件"""
        try:
            return device_manager.adb_manager.execute_command(
                device_id, f"cat {apk_path}", binary_output=True
            )
        except:
            return None
    
    def _backup_app_data(self, device_manager, device_id: str, package_name: str, backup_path: Path):
        """备份应用数据"""
        try:
            backup_path.mkdir(exist_ok=True)
            
            # 备份应用数据目录
            data_paths = [
                f"/data/data/{package_name}",
                f"/sdcard/Android/data/{package_name}"
            ]
            
            for data_path in data_paths:
                try:
                    result = device_manager.adb_manager.execute_command(
                        device_id, f"ls {data_path} 2>/dev/null"
                    )
                    
                    if result:
                        # 创建备份记录
                        backup_info = {
                            'path': data_path,
                            'backup_time': datetime.now().isoformat(),
                            'files': result.split('\n')
                        }
                        
                        with open(backup_path / f"{os.path.basename(data_path)}_info.json", 'w') as f:
                            json.dump(backup_info, f, indent=2)
                
                except:
                    continue
        
        except Exception as e:
            self.logger.error(f"备份应用数据失败: {e}")
    
    def _disable_application(self, device_manager, device_id: str, package_name: str) -> bool:
        """禁用应用"""
        try:
            result = device_manager.adb_manager.execute_command(
                device_id, f"pm disable-user --user 0 {package_name}"
            )
            
            return 'new state: disabled' in (result or '')
        except:
            return False
    
    def _restore_application(self, device_manager, device_id: str, item: QuarantineItem) -> bool:
        """恢复应用"""
        try:
            if not item.restoration_info:
                return False
            
            # 启用应用
            if item.restoration_info.get('disabled'):
                enable_result = device_manager.adb_manager.execute_command(
                    device_id, f"pm enable {item.package_name}"
                )
                
                return 'new state: enabled' in (enable_result or '')
            
            return True
        except:
            return False
    
    def _restore_file(self, item: QuarantineItem) -> bool:
        """恢复文件"""
        try:
            quarantine_path = Path(item.quarantine_path)
            original_path = Path(item.original_path)
            
            if not quarantine_path.exists():
                return False
            
            # 创建目标目录
            original_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 恢复文件
            shutil.copy2(quarantine_path, original_path)
            
            # 恢复权限
            if item.restoration_info:
                try:
                    permissions = int(item.restoration_info.get('original_permissions', '644'), 8)
                    os.chmod(original_path, permissions)
                except:
                    pass
            
            return True
        except:
            return False
    
    def _log_quarantine_action(self, action: str, item: QuarantineItem):
        """记录隔离操作日志"""
        if not self.config['log_quarantine_actions']:
            return
        
        try:
            log_file = self.quarantine_base_path / "logs" / f"quarantine_{datetime.now().strftime('%Y%m')}.log"
            log_file.parent.mkdir(exist_ok=True)
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'item_id': item.item_id,
                'package_name': item.package_name,
                'original_path': item.original_path,
                'reason': item.reason.value,
                'status': item.status.value
            }
            
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        
        except Exception as e:
            self.logger.error(f"记录隔离日志失败: {e}")
