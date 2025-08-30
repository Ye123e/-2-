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
from typing import List, Optional, Dict, Callable, Any
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
    
    def validate_device_connection(self, device_id: str) -> Dict[str, bool]:
        """
        验证设备连接状态和各项功能
        
        Args:
            device_id: 设备ID
            
        Returns:
            验证结果字典
        """
        validation_results = {
            'adb_connected': False,
            'authorized': False,
            'shell_access': False,
            'storage_accessible': False,
            'system_readable': False
        }
        
        try:
            # 检查设备是否在设备列表中
            if device_id not in self.adb_manager.get_adb_devices():
                self.logger.warning(f"设备不在ADB设备列表中: {device_id}")
                return validation_results
            
            validation_results['adb_connected'] = True
            
            # 检查设备授权状态
            device = self.adb_manager.connect_device(device_id)
            if device:
                validation_results['authorized'] = True
                
                # 测试shell访问
                result = self.adb_manager.execute_command(device_id, 'echo "test"')
                if result and 'test' in result:
                    validation_results['shell_access'] = True
                    
                    # 测试存储访问
                    storage_result = self.adb_manager.execute_command(device_id, 'df /data')
                    if storage_result and '/data' in storage_result:
                        validation_results['storage_accessible'] = True
                    
                    # 测试系统信息读取
                    system_result = self.adb_manager.execute_command(device_id, 'getprop ro.build.version.release')
                    if system_result and system_result.strip():
                        validation_results['system_readable'] = True
                        
        except Exception as e:
            self.logger.error(f"设备验证异常: {device_id}, 错误: {e}")
            
        return validation_results
    
    def get_device_health_status(self, device_id: str) -> Dict[str, Any]:
        """
        获取设备健康状态
        
        Args:
            device_id: 设备ID
            
        Returns:
            设备健康状态信息
        """
        health_status = {
            'overall_status': 'unknown',
            'connection_quality': 'unknown',
            'response_time': 0,
            'battery_level': 0,
            'temperature': 0,
            'memory_usage': 0,
            'storage_usage': 0,
            'issues': []
        }
        
        try:
            start_time = time.time()
            
            # 测试响应时间
            result = self.adb_manager.execute_command(device_id, 'echo "ping"')
            response_time = time.time() - start_time
            health_status['response_time'] = round(response_time * 1000, 2)  # 毫秒
            
            if not result or 'ping' not in result:
                health_status['issues'].append('设备响应异常')
                health_status['overall_status'] = 'poor'
                return health_status
            
            # 获取电池信息
            battery_info = self.adb_manager.execute_command(device_id, 'dumpsys battery | grep level')
            if battery_info:
                import re
                battery_match = re.search(r'level: (\d+)', battery_info)
                if battery_match:
                    health_status['battery_level'] = int(battery_match.group(1))
            
            # 获取温度信息
            temp_info = self.adb_manager.execute_command(device_id, 'cat /sys/class/thermal/thermal_zone0/temp')
            if temp_info and temp_info.strip().isdigit():
                # 温度通常以毫摄氏度为单位
                health_status['temperature'] = int(temp_info.strip()) / 1000
            
            # 获取内存使用情况
            mem_info = self.adb_manager.execute_command(device_id, 'cat /proc/meminfo | head -3')
            if mem_info:
                lines = mem_info.strip().split('\n')
                if len(lines) >= 2:
                    # 解析内存信息
                    total_match = re.search(r'MemTotal:\s+(\d+)', lines[0])
                    available_match = re.search(r'MemAvailable:\s+(\d+)', lines[1]) or re.search(r'MemFree:\s+(\d+)', lines[1])
                    
                    if total_match and available_match:
                        total_mem = int(total_match.group(1))
                        available_mem = int(available_match.group(1))
                        health_status['memory_usage'] = round((total_mem - available_mem) / total_mem * 100, 1)
            
            # 获取存储使用情况
            storage_info = self._get_storage_info(device_id)
            if storage_info['total'] > 0:
                used_storage = storage_info['total'] - storage_info['free']
                health_status['storage_usage'] = round(used_storage / storage_info['total'] * 100, 1)
            
            # 评估连接质量
            if response_time < 1.0:
                health_status['connection_quality'] = 'excellent'
            elif response_time < 2.0:
                health_status['connection_quality'] = 'good'
            elif response_time < 5.0:
                health_status['connection_quality'] = 'fair'
            else:
                health_status['connection_quality'] = 'poor'
                health_status['issues'].append('设备响应缓慢')
            
            # 评估整体状态
            issues_count = len(health_status['issues'])
            if issues_count == 0 and health_status['connection_quality'] in ['excellent', 'good']:
                health_status['overall_status'] = 'good'
            elif issues_count <= 1 and health_status['connection_quality'] in ['good', 'fair']:
                health_status['overall_status'] = 'fair'
            else:
                health_status['overall_status'] = 'poor'
            
            # 添加具体的健康检查
            if health_status['battery_level'] > 0 and health_status['battery_level'] < 20:
                health_status['issues'].append('电池电量过低')
            
            if health_status['temperature'] > 45:
                health_status['issues'].append('设备温度过高')
            
            if health_status['memory_usage'] > 90:
                health_status['issues'].append('内存使用率过高')
            
            if health_status['storage_usage'] > 90:
                health_status['issues'].append('存储空间不足')
                
        except Exception as e:
            self.logger.error(f"获取设备健康状态失败: {device_id}, 错误: {e}")
            health_status['issues'].append(f'健康检查失败: {str(e)}')
            health_status['overall_status'] = 'error'
            
        return health_status
    
    def test_device_connectivity(self, device_id: str) -> bool:
        """
        测试设备连通性
        
        Args:
            device_id: 设备ID
            
        Returns:
            连通性测试结果
        """
        try:
            # 执行简单的echo命令测试
            result = self.adb_manager.execute_command(device_id, 'echo "connectivity_test"')
            return result is not None and 'connectivity_test' in result
        except Exception as e:
            self.logger.error(f"设备连通性测试失败: {device_id}, 错误: {e}")
            return False
    
    def get_device_capabilities(self, device_id: str) -> Dict[str, bool]:
        """
        获取设备能力信息
        
        Args:
            device_id: 设备ID
            
        Returns:
            设备能力字典
        """
        capabilities = {
            'root_access': False,
            'package_manager': False,
            'file_system_access': False,
            'network_access': False,
            'system_properties': False,
            'service_control': False
        }
        
        try:
            # 测试ROOT权限
            root_result = self.adb_manager.execute_command(device_id, 'id')
            if root_result and 'uid=0(root)' in root_result:
                capabilities['root_access'] = True
            
            # 测试包管理器
            pm_result = self.adb_manager.execute_command(device_id, 'pm list packages | head -1')
            if pm_result and 'package:' in pm_result:
                capabilities['package_manager'] = True
            
            # 测试文件系统访问
            fs_result = self.adb_manager.execute_command(device_id, 'ls /system')
            if fs_result and ('bin' in fs_result or 'lib' in fs_result):
                capabilities['file_system_access'] = True
            
            # 测试网络访问
            network_result = self.adb_manager.execute_command(device_id, 'ping -c 1 8.8.8.8')
            if network_result and ('1 packets transmitted' in network_result or 'ttl=' in network_result.lower()):
                capabilities['network_access'] = True
            
            # 测试系统属性访问
            prop_result = self.adb_manager.execute_command(device_id, 'getprop ro.build.version.release')
            if prop_result and prop_result.strip():
                capabilities['system_properties'] = True
            
            # 测试服务控制（需要root权限）
            if capabilities['root_access']:
                service_result = self.adb_manager.execute_command(device_id, 'service list | head -1')
                if service_result:
                    capabilities['service_control'] = True
                    
        except Exception as e:
            self.logger.error(f"获取设备能力信息失败: {device_id}, 错误: {e}")
            
        return capabilities