#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API服务层
提供RESTful API接口和业务逻辑封装
"""

import json
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from flask import Flask, request, jsonify, make_response  # pyright: ignore[reportMissingImports]
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError  # pyright: ignore[reportMissingImports]
from functools import wraps

from ..core.device_manager import DeviceManager
from ..core.virus_scan_engine import VirusScanEngine
from ..core.threat_analysis_engine import ThreatAnalysisEngine
from ..core.vulnerability_detection_engine import VulnerabilityDetectionEngine
from ..core.enhanced_repair_engine import EnhancedRepairEngine
from ..core.realtime_monitoring_engine import RealTimeMonitoringEngine
from ..core.repair_task_manager import RepairTaskManager, TaskPriority
from ..models import ThreatLevel, TaskStatus
from ..utils.logger import LoggerMixin


class APIResponse:
    """API响应格式化器"""
    
    @staticmethod
    def success(data: Any = None, message: str = "操作成功") -> Dict[str, Any]:
        """成功响应"""
        return {
            "code": 200,
            "success": True,
            "message": message,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def error(code: int = 500, message: str = "操作失败", details: Any = None) -> Dict[str, Any]:
        """错误响应"""
        return {
            "code": code,
            "success": False,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def paginated(data: List[Any], total: int, page: int, page_size: int) -> Dict[str, Any]:
        """分页响应"""
        return APIResponse.success({
            "items": data,
            "pagination": {
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": (total + page_size - 1) // page_size
            }
        })


def validate_json(f):
    """JSON数据验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.content_type != 'application/json':
            return jsonify(APIResponse.error(400, "Content-Type必须是application/json")), 400
        try:
            request.json
        except BadRequest:
            return jsonify(APIResponse.error(400, "无效的JSON数据")), 400
        return f(*args, **kwargs)
    return decorated_function


def validate_device_id(f):
    """设备ID验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        device_id = request.view_args.get('device_id')
        if not device_id:
            return jsonify(APIResponse.error(400, "缺少设备ID参数")), 400
        return f(*args, **kwargs)
    return decorated_function


class SecurityAPIService(LoggerMixin):
    """安全API服务"""
    
    def __init__(self):
        """初始化API服务"""
        self.app = Flask(__name__)
        self.app.config['JSON_AS_ASCII'] = False  # 支持中文
        
        # 初始化核心组件
        self.device_manager = DeviceManager()
        self.virus_scan_engine = VirusScanEngine(self.device_manager)
        self.threat_analysis_engine = ThreatAnalysisEngine()
        self.vulnerability_engine = VulnerabilityDetectionEngine(self.device_manager)
        self.repair_engine = EnhancedRepairEngine(self.device_manager)
        self.monitoring_engine = RealTimeMonitoringEngine(self.device_manager)
        self.task_manager = RepairTaskManager(self.device_manager)
        
        # 注册路由
        self._register_routes()
        
        # 错误处理
        self._register_error_handlers()
    
    def _register_routes(self):
        """注册API路由"""
        
        # 设备管理API
        @self.app.route('/api/devices', methods=['GET'])
        def get_devices():
            """获取设备列表"""
            try:
                devices = self.device_manager.get_devices()  # pyright: ignore[reportAttributeAccessIssue]
                device_list = []
                
                for device in devices:
                    device_dict = {
                        'device_id': device.device_id,
                        'model': device.model,
                        'android_version': device.android_version,
                        'storage_total': device.storage_total,
                        'storage_free': device.storage_free,
                        'storage_usage_percent': device.storage_usage_percent,
                        'root_status': device.root_status,
                        'connection_type': device.connection_type.value,
                        'last_connected': device.last_connected.isoformat() if device.last_connected else None
                    }
                    device_list.append(device_dict)
                
                return jsonify(APIResponse.success(device_list))
            
            except Exception as e:
                self.logger.error(f"获取设备列表失败: {e}")
                return jsonify(APIResponse.error(500, "获取设备列表失败")), 500
        
        @self.app.route('/api/devices/<device_id>', methods=['GET'])
        @validate_device_id
        def get_device_info(device_id: str):
            """获取设备详细信息"""
            try:
                device = self.device_manager.get_device(device_id)
                if not device:
                    return jsonify(APIResponse.error(404, "设备未找到")), 404
                
                device_info = {
                    'device_id': device.device_id,
                    'model': device.model,
                    'manufacturer': device.manufacturer,
                    'android_version': device.android_version,
                    'build_number': device.build_number,
                    'cpu_arch': device.cpu_arch,
                    'screen_resolution': device.screen_resolution,
                    'storage_total': device.storage_total,
                    'storage_free': device.storage_free,
                    'storage_used': device.storage_used,
                    'storage_usage_percent': device.storage_usage_percent,
                    'root_status': device.root_status,
                    'connection_type': device.connection_type.value,
                    'last_connected': device.last_connected.isoformat() if device.last_connected else None
                }
                
                return jsonify(APIResponse.success(device_info))
            
            except Exception as e:
                self.logger.error(f"获取设备信息失败: {e}")
                return jsonify(APIResponse.error(500, "获取设备信息失败")), 500
        
        # 病毒扫描API
        @self.app.route('/api/devices/<device_id>/virus-scan', methods=['POST'])
        @validate_device_id
        @validate_json
        def start_virus_scan(device_id: str):
            """启动病毒扫描"""
            try:
                data = request.json or {}
                scan_options = data.get('scan_options', {
                    'use_yara': True,
                    'use_clamav': True,
                    'use_heuristic': True
                })
                
                # 异步启动扫描
                report = self.virus_scan_engine.scan_device(device_id, scan_options)
                
                if report:
                    scan_result = {
                        'scan_id': f"virus_scan_{device_id}_{int(time.time())}",
                        'device_id': report.device_id,  # pyright: ignore[reportAttributeAccessIssue]
                        'malware_count': report.malware_count,
                        'suspicious_count': report.suspicious_count,  # pyright: ignore[reportAttributeAccessIssue]
                        'threat_level': report.threat_level.value,  # pyright: ignore[reportAttributeAccessIssue]
                        'detected_threats': [threat.to_dict() if hasattr(threat, 'to_dict') else str(threat) 
                                           for threat in report.detected_threats],  # pyright: ignore[reportAttributeAccessIssue]
                        'scan_summary': report.scan_summary  # pyright: ignore[reportAttributeAccessIssue]  # pyright: ignore[reportAttributeAccessIssue]
                    }
                    
                    return jsonify(APIResponse.success(scan_result, "病毒扫描完成"))
                else:
                    return jsonify(APIResponse.error(500, "病毒扫描启动失败")), 500
            
            except Exception as e:
                self.logger.error(f"病毒扫描失败: {e}")
                return jsonify(APIResponse.error(500, f"病毒扫描失败: {str(e)}")), 500
        
        # 威胁分析API
        @self.app.route('/api/devices/<device_id>/threat-analysis', methods=['POST'])
        @validate_device_id
        @validate_json
        def analyze_threat(device_id: str):
            """威胁分析"""
            try:
                data = request.json
                app_info = data.get('app_info')
                
                if not app_info:
                    return jsonify(APIResponse.error(400, "缺少应用信息")), 400
                
                assessment = self.threat_analysis_engine.analyze_app_info(app_info)
                
                result = {
                    'app_package': assessment.app_package,
                    'risk_score': assessment.risk_score,
                    'threat_level': assessment.threat_level.value,
                    'confidence': assessment.confidence,
                    'indicators': [indicator.to_dict() if hasattr(indicator, 'to_dict')   # pyright: ignore[reportAttributeAccessIssue]
                                 else str(indicator) for indicator in assessment.indicators],
                    'mitigation_actions': [action.to_dict() if hasattr(action, 'to_dict')  # pyright: ignore[reportAttributeAccessIssue]
                                         else str(action) for action in assessment.mitigation_actions],
                    'assessment_time': assessment.assessment_time.isoformat() if assessment.assessment_time else None,
                    'details': assessment.details
                }
                
                return jsonify(APIResponse.success(result, "威胁分析完成"))
            
            except Exception as e:
                self.logger.error(f"威胁分析失败: {e}")
                return jsonify(APIResponse.error(500, f"威胁分析失败: {str(e)}")), 500
        
        # 漏洞扫描API
        @self.app.route('/api/devices/<device_id>/vulnerability-scan', methods=['POST'])
        @validate_device_id
        def scan_vulnerabilities(device_id: str):
            """漏洞扫描"""
            try:
                vuln_report = self.vulnerability_engine.scan_vulnerabilities(device_id)
                
                if vuln_report:
                    result = vuln_report.to_dict()
                    return jsonify(APIResponse.success(result, "漏洞扫描完成"))
                else:
                    return jsonify(APIResponse.error(500, "漏洞扫描失败")), 500
            
            except Exception as e:
                self.logger.error(f"漏洞扫描失败: {e}")
                return jsonify(APIResponse.error(500, f"漏洞扫描失败: {str(e)}")), 500
        
        # 修复任务API
        @self.app.route('/api/devices/<device_id>/repair', methods=['POST'])
        @validate_device_id
        @validate_json
        def create_repair_task(device_id: str):
            """创建修复任务"""
            try:
                data = request.json
                repair_type = data.get('repair_type', 'VULNERABILITY_REPAIR')
                auto_repair = data.get('auto_repair', True)
                priority = data.get('priority', 'MEDIUM')
                
                try:
                    priority_enum = TaskPriority[priority.upper()]
                except KeyError:
                    priority_enum = TaskPriority.MEDIUM
                
                if repair_type == 'VULNERABILITY_REPAIR':
                    task_id = self.task_manager.create_vulnerability_repair_task(
                        device_id, auto_repair, priority_enum
                    )
                elif repair_type == 'SYSTEM_HARDENING':
                    hardening_types = data.get('hardening_types')
                    task_id = self.task_manager.create_system_hardening_task(
                        device_id, hardening_types, priority_enum
                    )
                else:
                    return jsonify(APIResponse.error(400, f"不支持的修复类型: {repair_type}")), 400
                
                return jsonify(APIResponse.success({
                    'task_id': task_id,
                    'repair_type': repair_type,
                    'device_id': device_id,
                    'status': 'PENDING'
                }, "修复任务已创建"))
            
            except Exception as e:
                self.logger.error(f"创建修复任务失败: {e}")
                return jsonify(APIResponse.error(500, f"创建修复任务失败: {str(e)}")), 500
        
        @self.app.route('/api/repair/tasks/<task_id>', methods=['GET'])
        def get_repair_task_status(task_id: str):
            """获取修复任务状态"""
            try:
                task = self.task_manager.task_executor.task_queue.task_registry.get(task_id)
                if not task:
                    # 尝试从repair_engine获取
                    task = self.repair_engine.get_repair_status(task_id)
                
                if not task:
                    return jsonify(APIResponse.error(404, "任务未找到")), 404
                
                task_info = {
                    'task_id': task.task_id,
                    'device_id': task.device_id,
                    'task_type': task.task_type,
                    'status': task.status.value if hasattr(task.status, 'value') else str(task.status),
                    'progress': task.progress,
                    'start_time': task.start_time.isoformat() if task.start_time else None,
                    'end_time': task.end_time.isoformat() if task.end_time else None,
                    'duration': task.duration,
                    'logs': task.logs[-10:],  # 最近10条日志
                    'error_message': task.error_message,
                    'details': task.details
                }
                
                return jsonify(APIResponse.success(task_info))
            
            except Exception as e:
                self.logger.error(f"获取任务状态失败: {e}")
                return jsonify(APIResponse.error(500, "获取任务状态失败")), 500
        
        # 批量修复API
        @self.app.route('/api/repair/batch', methods=['POST'])
        @validate_json
        def create_batch_repair():
            """创建批量修复作业"""
            try:
                data = request.json
                devices = data.get('devices', [])
                repair_types = data.get('repair_types', ['VULNERABILITY_REPAIR'])
                auto_repair = data.get('auto_repair', True)
                parallel_execution = data.get('parallel_execution', True)
                priority = data.get('priority', 'MEDIUM')
                
                if not devices:
                    return jsonify(APIResponse.error(400, "设备列表不能为空")), 400
                
                try:
                    priority_enum = TaskPriority[priority.upper()]
                except KeyError:
                    priority_enum = TaskPriority.MEDIUM
                
                job_id = self.task_manager.create_batch_repair_job(
                    devices, repair_types, priority_enum, auto_repair, parallel_execution
                )
                
                return jsonify(APIResponse.success({
                    'job_id': job_id,
                    'devices': devices,
                    'repair_types': repair_types,
                    'status': 'PENDING'
                }, "批量修复作业已创建"))
            
            except Exception as e:
                self.logger.error(f"创建批量修复失败: {e}")
                return jsonify(APIResponse.error(500, f"创建批量修复失败: {str(e)}")), 500
        
        # 监控API
        @self.app.route('/api/monitoring/start', methods=['POST'])
        @validate_json
        def start_monitoring():
            """启动监控"""
            try:
                data = request.json or {}
                device_ids = data.get('device_ids')
                
                self.monitoring_engine.start_monitoring(device_ids)  # pyright: ignore[reportArgumentType]  # pyright: ignore[reportArgumentType]
                
                return jsonify(APIResponse.success({
                    'monitoring_enabled': True,
                    'monitored_devices': len(device_ids) if device_ids else 0
                }, "监控已启动"))
            
            except Exception as e:
                self.logger.error(f"启动监控失败: {e}")
                return jsonify(APIResponse.error(500, f"启动监控失败: {str(e)}")), 500
        
        @self.app.route('/api/monitoring/stop', methods=['POST'])
        def stop_monitoring():
            """停止监控"""
            try:
                self.monitoring_engine.stop_monitoring()
                
                return jsonify(APIResponse.success({
                    'monitoring_enabled': False
                }, "监控已停止"))
            
            except Exception as e:
                self.logger.error(f"停止监控失败: {e}")
                return jsonify(APIResponse.error(500, f"停止监控失败: {str(e)}")), 500
        
        @self.app.route('/api/monitoring/status', methods=['GET'])
        def get_monitoring_status():
            """获取监控状态"""
            try:
                status = self.monitoring_engine.get_monitoring_status()
                return jsonify(APIResponse.success(status))
            
            except Exception as e:
                self.logger.error(f"获取监控状态失败: {e}")
                return jsonify(APIResponse.error(500, "获取监控状态失败")), 500
        
        @self.app.route('/api/monitoring/events', methods=['GET'])
        def get_security_events():
            """获取安全事件"""
            try:
                limit = request.args.get('limit', 50, type=int)
                events = self.monitoring_engine.get_recent_events(limit)
                
                event_list = []
                for event in events:
                    event_dict = event.to_dict() if hasattr(event, 'to_dict') else {  # pyright: ignore[reportAttributeAccessIssue]  # pyright: ignore[reportAttributeAccessIssue]
                        'event_id': event.event_id,
                        'event_type': event.event_type,
                        'device_id': event.device_id,
                        'severity': event.severity,
                        'description': event.description,
                        'timestamp': event.timestamp.isoformat(),
                        'acknowledged': event.acknowledged
                    }
                    event_list.append(event_dict)
                
                return jsonify(APIResponse.success(event_list))
            
            except Exception as e:
                self.logger.error(f"获取安全事件失败: {e}")
                return jsonify(APIResponse.error(500, "获取安全事件失败")), 500
        
        # 统计API
        @self.app.route('/api/statistics', methods=['GET'])
        def get_statistics():
            """获取系统统计信息"""
            try:
                task_stats = self.task_manager.get_task_statistics()
                repair_stats = self.repair_engine.get_repair_stats()
                monitoring_status = self.monitoring_engine.get_monitoring_status()
                
                statistics = {
                    'devices': {
                        'total': len(self.device_manager.get_devices()),  # pyright: ignore[reportAttributeAccessIssue]
                        'online': len([d for d in self.device_manager.get_devices() if d.connection_type.value != 'UNKNOWN'])  # pyright: ignore[reportAttributeAccessIssue]
                    },
                    'tasks': task_stats,
                    'repairs': repair_stats,
                    'monitoring': monitoring_status,
                    'timestamp': datetime.now().isoformat()
                }
                
                return jsonify(APIResponse.success(statistics))
            
            except Exception as e:
                self.logger.error(f"获取统计信息失败: {e}")
                return jsonify(APIResponse.error(500, "获取统计信息失败")), 500
    
    def _register_error_handlers(self):
        """注册错误处理器"""
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify(APIResponse.error(404, "接口未找到")), 404
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify(APIResponse.error(400, "请求参数错误")), 400
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify(APIResponse.error(500, "服务器内部错误")), 500
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """启动API服务"""
        self.logger.info(f"启动API服务，地址: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


# API服务实例
api_service = SecurityAPIService()