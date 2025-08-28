#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备管理器模块
负责Android设备的连接、检测和状态监控
"""

import subprocess
import re
import time
import threading
from typing import List, Optional, Dict, Callable
from datetime import datetime

from adb_shell.adb_device import AdbDeviceTcp, AdbDeviceUsb
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

from ..models import DeviceInfo, ConnectionType
from ..utils.logger import LoggerMixin

class ADBManager(LoggerMixin):
    """ADB连接管理器"""
    
    def __init__(self, timeout: int = 30, port: int = 5037, adb_path: Optional[str] = None):
        """
        初始化ADB管理器
        
        Args:
            timeout: 连接超时时间（秒）
            port: ADB服务端口
            adb_path: ADB可执行文件路径
        """
        self.timeout = timeout
        self.port = port
        self.adb_path = adb_path or 'adb'  # 如果未指定路径，使用默认命令
        self.connected_devices: Dict[str, AdbDeviceUsb] = {}
        self._signer = None
        self._init_signer()
    
    def _init_signer(self):
        """初始化RSA签名器"""
        try:
            self._signer = PythonRSASigner.FromRSAKeyPath("~/.android/adbkey")
        except Exception as e:
            self.logger.warning(f"无法加载ADB密钥，将使用默认签名器: {e}")
            self._signer = PythonRSASigner.FromRSAKeyPath(None)
    
    def get_adb_devices(self) -> List[str]:
        """
        获取连接的ADB设备列表
        
        Returns:
            设备ID列表
        """
        try:
            result = subprocess.run(
                [self.adb_path, 'devices'],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"ADB命令执行失败: {result.stderr}")
                return []
            
            devices = []
            lines = result.stdout.strip().split('\n')[1:]  # 跳过标题行
            
            for line in lines:
                if line.strip() and '\tdevice' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
            
            return devices
            
        except subprocess.TimeoutExpired:
            self.logger.error("ADB设备检测超时")
            return []
        except FileNotFoundError:
            self.logger.error("未找到ADB命令，请确保Android SDK已安装并添加到PATH")
            return []
        except Exception as e:
            self.logger.error(f"获取ADB设备失败: {e}")
            return []
    
    def connect_device(self, device_id: str) -> Optional[AdbDeviceUsb]:
        """
        连接到指定设备
        
        Args:
            device_id: 设备ID
            
        Returns:
            连接的设备对象，失败返回None
        """
        try:
            if device_id in self.connected_devices:
                return self.connected_devices[device_id]
            
            # 尝试USB连接
            device = AdbDeviceUsb()
            if device.connect(rsa_keys=[self._signer], timeout=self.timeout):
                self.connected_devices[device_id] = device
                self.logger.info(f"成功连接到设备: {device_id}")
                return device
            else:
                self.logger.error(f"连接设备失败: {device_id}")
                return None
                
        except Exception as e:
            self.logger.error(f"连接设备异常: {device_id}, 错误: {e}")
            return None
    
    def disconnect_device(self, device_id: str):
        """
        断开设备连接
        
        Args:
            device_id: 设备ID
        """
        try:
            if device_id in self.connected_devices:
                device = self.connected_devices[device_id]
                device.close()
                del self.connected_devices[device_id]
                self.logger.info(f"已断开设备连接: {device_id}")
        except Exception as e:
            self.logger.error(f"断开设备连接失败: {device_id}, 错误: {e}")
    
    def execute_command(self, device_id: str, command: str) -> Optional[str]:
        """
        在设备上执行ADB命令
        
        Args:
            device_id: 设备ID
            command: 要执行的命令
            
        Returns:
            命令输出，失败返回None
        """
        try:
            device = self.connected_devices.get(device_id)
            if not device:
                self.logger.error(f"设备未连接: {device_id}")
                return None
            
            result = device.shell(command, timeout_s=self.timeout)
            return result.decode('utf-8') if isinstance(result, bytes) else result
            
        except Exception as e:
            self.logger.error(f"执行命令失败: {command}, 错误: {e}")
            return None

class DeviceManager(LoggerMixin):
    """设备管理器"""
    
    def __init__(self, adb_timeout: int = 30, adb_port: int = 5037, adb_path: Optional[str] = None):
        """
        初始化设备管理器
        
        Args:
            adb_timeout: ADB连接超时时间
            adb_port: ADB服务端口
            adb_path: ADB可执行文件路径
        """
        self.adb_manager = ADBManager(adb_timeout, adb_port, adb_path)
        self.devices: Dict[str, DeviceInfo] = {}
        self.device_callbacks: List[Callable[[str, DeviceInfo], None]] = []
        self._monitoring = False
        self._monitor_thread = None
    
    def add_device_callback(self, callback: Callable[[str, DeviceInfo], None]):
        """
        添加设备状态变化回调函数
        
        Args:
            callback: 回调函数，参数为(action, device_info)
                     action可能的值: 'connected', 'disconnected', 'updated'
        """
        self.device_callbacks.append(callback)
    
    def _notify_callbacks(self, action: str, device_info: DeviceInfo):
        """通知所有回调函数"""
        for callback in self.device_callbacks:
            try:
                callback(action, device_info)
            except Exception as e:
                self.logger.error(f"设备回调执行失败: {e}")
    
    def scan_devices(self) -> List[DeviceInfo]:
        """
        扫描连接的设备
        
        Returns:
            设备信息列表
        """
        device_ids = self.adb_manager.get_adb_devices()
        current_devices = {}
        
        for device_id in device_ids:
            if device_id in self.devices:
                # 更新现有设备信息
                device_info = self.devices[device_id]
                device_info.last_connected = datetime.now()
                current_devices[device_id] = device_info
            else:
                # 新设备，获取详细信息
                device_info = self._get_device_info(device_id)
                if device_info:
                    current_devices[device_id] = device_info
                    self._notify_callbacks('connected', device_info)
        
        # 检查断开的设备
        for device_id in self.devices:
            if device_id not in current_devices:
                self._notify_callbacks('disconnected', self.devices[device_id])
        
        self.devices = current_devices
        return list(self.devices.values())
    
    def _get_device_info(self, device_id: str) -> Optional[DeviceInfo]:
        """
        获取设备详细信息
        
        Args:
            device_id: 设备ID
            
        Returns:
            设备信息对象
        """
        try:
            device = self.adb_manager.connect_device(device_id)
            if not device:
                return None
            
            # 获取设备属性
            model = self._get_device_property(device_id, 'ro.product.model') or 'Unknown'
            android_version = self._get_device_property(device_id, 'ro.build.version.release') or 'Unknown'
            build_number = self._get_device_property(device_id, 'ro.build.display.id') or 'Unknown'
            manufacturer = self._get_device_property(device_id, 'ro.product.manufacturer') or 'Unknown'
            cpu_arch = self._get_device_property(device_id, 'ro.product.cpu.abi') or 'Unknown'
            
            # 检查ROOT状态
            root_status = self._check_root_status(device_id)
            
            # 获取存储信息
            storage_info = self._get_storage_info(device_id)
            
            # 获取屏幕分辨率
            screen_resolution = self._get_screen_resolution(device_id)
            
            device_info = DeviceInfo(
                device_id=device_id,
                model=model,
                android_version=android_version,
                build_number=build_number,
                root_status=root_status,
                storage_total=storage_info.get('total', 0),
                storage_free=storage_info.get('free', 0),
                connection_type=ConnectionType.USB,
                manufacturer=manufacturer,
                cpu_arch=cpu_arch,
                screen_resolution=screen_resolution
            )
            
            self.logger.info(f"获取设备信息成功: {model} ({device_id})")
            return device_info
            
        except Exception as e:
            self.logger.error(f"获取设备信息失败: {device_id}, 错误: {e}")
            return None
    
    def _get_device_property(self, device_id: str, property_name: str) -> Optional[str]:
        """获取设备属性"""
        result = self.adb_manager.execute_command(device_id, f'getprop {property_name}')
        return result.strip() if result else None
    
    def _check_root_status(self, device_id: str) -> bool:
        """检查设备ROOT状态"""
        result = self.adb_manager.execute_command(device_id, 'id')
        return 'uid=0(root)' in (result or '')
    
    def _get_storage_info(self, device_id: str) -> Dict[str, int]:
        """获取存储空间信息"""
        try:
            result = self.adb_manager.execute_command(device_id, 'df /data')
            if not result:
                return {'total': 0, 'free': 0}
            
            lines = result.strip().split('\n')
            if len(lines) < 2:
                return {'total': 0, 'free': 0}
            
            # 解析df输出
            data_line = lines[1]
            parts = data_line.split()
            if len(parts) >= 4:
                total = int(parts[1]) * 1024  # 转换为字节
                free = int(parts[3]) * 1024   # 转换为字节
                return {'total': total, 'free': free}
            
            return {'total': 0, 'free': 0}
            
        except Exception as e:
            self.logger.error(f"获取存储信息失败: {e}")
            return {'total': 0, 'free': 0}
    
    def _get_screen_resolution(self, device_id: str) -> str:
        """获取屏幕分辨率"""
        result = self.adb_manager.execute_command(device_id, 'wm size')
        if result:
            match = re.search(r'(\d+x\d+)', result)
            if match:
                return match.group(1)
        return 'Unknown'
    
    def get_device(self, device_id: str) -> Optional[DeviceInfo]:
        """
        获取指定设备信息
        
        Args:
            device_id: 设备ID
            
        Returns:
            设备信息对象
        """
        return self.devices.get(device_id)
    
    def get_connected_devices(self) -> List[DeviceInfo]:
        """获取所有连接的设备"""
        return list(self.devices.values())
    
    def disconnect_device(self, device_id: str):
        """断开设备连接"""
        self.adb_manager.disconnect_device(device_id)
        if device_id in self.devices:
            device_info = self.devices[device_id]
            del self.devices[device_id]
            self._notify_callbacks('disconnected', device_info)
    
    def start_monitoring(self, interval: int = 5):
        """
        开始设备监控
        
        Args:
            interval: 监控间隔（秒）
        """
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_devices,
            args=(interval,),
            daemon=True
        )
        self._monitor_thread.start()
        self.logger.info("设备监控已启动")
    
    def stop_monitoring(self):
        """停止设备监控"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
        self.logger.info("设备监控已停止")
    
    def _monitor_devices(self, interval: int):
        """设备监控线程"""
        while self._monitoring:
            try:
                self.scan_devices()
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"设备监控异常: {e}")
                time.sleep(interval)