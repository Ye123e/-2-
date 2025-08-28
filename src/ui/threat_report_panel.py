#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁报告面板和修复操作界面
提供Web界面展示威胁报告、修复操作和系统状态
"""

from flask import Flask, render_template, request, jsonify, session
from datetime import datetime
from typing import Dict, List, Any
import json

from ..api.api_service import SecurityAPIService
from ..utils.logger import LoggerMixin


class ThreatReportPanel(LoggerMixin):
    """威胁报告面板"""
    
    def __init__(self, api_service: SecurityAPIService):
        self.api_service = api_service
        self.app = Flask(__name__, 
                        template_folder='../templates',
                        static_folder='../static')
        self.app.secret_key = 'android_security_tool_2024'
        self._register_routes()
    
    def _register_routes(self):
        """注册路由"""
        
        @self.app.route('/')
        def dashboard():
            """主仪表板"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/dashboard/summary')
        def get_dashboard_summary():
            """获取仪表板摘要"""
            try:
                devices = self.api_service.get_connected_devices()
                total_devices = len(devices.get('devices', []))
                
                summary = {
                    'total_devices': total_devices,
                    'active_scans': 0,
                    'threats_detected': 0,
                    'repairs_completed': 0,
                    'last_update': datetime.now().isoformat()
                }
                
                return jsonify(summary)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/threats')
        def threats_page():
            """威胁报告页面"""
            return render_template('threats.html')
        
        @self.app.route('/api/threats/<device_id>')
        def get_device_threats(device_id):
            """获取设备威胁报告"""
            try:
                # 获取病毒扫描结果
                virus_scan = self.api_service.get_scan_report(device_id, 'virus_scan')
                
                # 获取威胁分析结果
                threat_analysis = self.api_service.get_scan_report(device_id, 'threat_analysis')
                
                # 获取漏洞检测结果
                vuln_scan = self.api_service.get_scan_report(device_id, 'vulnerability_scan')
                
                threats_summary = {
                    'device_id': device_id,
                    'scan_time': datetime.now().isoformat(),
                    'virus_threats': virus_scan.get('results', {}).get('threats', []),
                    'behavior_threats': threat_analysis.get('results', {}).get('threats', []),
                    'vulnerabilities': vuln_scan.get('results', {}).get('vulnerabilities', []),
                    'risk_score': threat_analysis.get('results', {}).get('risk_score', 0.0),
                    'threat_level': threat_analysis.get('results', {}).get('threat_level', 'LOW')
                }
                
                return jsonify(threats_summary)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/repairs')
        def repairs_page():
            """修复操作页面"""
            return render_template('repairs.html')
        
        @self.app.route('/api/repairs/execute', methods=['POST'])
        def execute_repair():
            """执行修复操作"""
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                repair_type = data.get('repair_type')
                repair_params = data.get('parameters', {})
                
                if repair_type == 'virus_removal':
                    result = self.api_service.remove_threat(device_id, repair_params)
                elif repair_type == 'vulnerability_fix':
                    result = self.api_service.fix_vulnerability(device_id, repair_params)
                elif repair_type == 'batch_repair':
                    result = self.api_service.execute_batch_repair(device_id, repair_params)
                else:
                    return jsonify({'error': '未知的修复类型'}), 400
                
                return jsonify(result)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/repairs/status/<task_id>')
        def get_repair_status(task_id):
            """获取修复状态"""
            try:
                status = self.api_service.get_repair_status(task_id)
                return jsonify(status)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/repairs/history/<device_id>')
        def get_repair_history(device_id):
            """获取修复历史"""
            try:
                history = self.api_service.get_repair_history(device_id)
                return jsonify(history)
            except Exception as e:
                return jsonify({'error': str(e)}), 500


class RepairOperationInterface(LoggerMixin):
    """修复操作界面"""
    
    def __init__(self, api_service: SecurityAPIService):
        self.api_service = api_service
        
    def generate_repair_recommendations(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成修复建议"""
        recommendations = []
        
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'MEDIUM')
            
            if threat_type == 'virus':
                recommendations.append({
                    'action': 'remove_virus',
                    'title': '移除病毒',
                    'description': f"检测到病毒: {threat.get('name', 'Unknown')}",
                    'severity': severity,
                    'auto_fix': True,
                    'estimated_time': '2-5分钟',
                    'parameters': {
                        'threat_id': threat.get('id'),
                        'file_path': threat.get('file_path')
                    }
                })
            
            elif threat_type == 'vulnerability':
                recommendations.append({
                    'action': 'fix_vulnerability', 
                    'title': '修复漏洞',
                    'description': f"发现安全漏洞: {threat.get('description', 'Unknown')}",
                    'severity': severity,
                    'auto_fix': threat.get('auto_fixable', False),
                    'estimated_time': '5-15分钟',
                    'parameters': {
                        'vuln_id': threat.get('id'),
                        'fix_type': threat.get('fix_type', 'config')
                    }
                })
            
            elif threat_type == 'malicious_app':
                recommendations.append({
                    'action': 'remove_app',
                    'title': '卸载恶意应用',
                    'description': f"检测到恶意应用: {threat.get('package_name', 'Unknown')}",
                    'severity': severity,
                    'auto_fix': True,
                    'estimated_time': '1-3分钟',
                    'parameters': {
                        'package_name': threat.get('package_name')
                    }
                })
        
        return recommendations
    
    def create_repair_plan(self, device_id: str, threats: List[Dict[str, Any]], 
                          strategy: str = 'priority') -> Dict[str, Any]:
        """创建修复计划"""
        try:
            recommendations = self.generate_repair_recommendations(threats)
            
            # 按策略排序
            if strategy == 'priority':
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                recommendations.sort(key=lambda x: severity_order.get(x['severity'], 3))
            
            plan = {
                'device_id': device_id,
                'total_items': len(recommendations),
                'estimated_time': sum(self._parse_time(r['estimated_time']) for r in recommendations),
                'recommendations': recommendations,
                'created_time': datetime.now().isoformat(),
                'strategy': strategy
            }
            
            return plan
            
        except Exception as e:
            self.logger.error(f"创建修复计划失败: {e}")
            return {'error': str(e)}
    
    def _parse_time(self, time_str: str) -> int:
        """解析时间字符串为分钟数"""
        if '-' in time_str:
            # 取平均值，如"2-5分钟"
            parts = time_str.split('-')
            min_time = int(parts[0])
            max_time = int(parts[1].split('分钟')[0])
            return (min_time + max_time) // 2
        else:
            return 5  # 默认值


class SecurityReportGenerator(LoggerMixin):
    """安全报告生成器"""
    
    def __init__(self):
        self.report_templates = {
            'summary': self._generate_summary_report,
            'detailed': self._generate_detailed_report,
            'compliance': self._generate_compliance_report
        }
    
    def generate_security_report(self, device_data: Dict[str, Any], 
                               report_type: str = 'summary') -> Dict[str, Any]:
        """生成安全报告"""
        try:
            generator = self.report_templates.get(report_type, self._generate_summary_report)
            return generator(device_data)
            
        except Exception as e:
            self.logger.error(f"生成安全报告失败: {e}")
            return {'error': str(e)}
    
    def _generate_summary_report(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成摘要报告"""
        threats = device_data.get('threats', [])
        vulnerabilities = device_data.get('vulnerabilities', [])
        
        # 统计威胁级别
        threat_stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for threat in threats:
            level = threat.get('severity', 'LOW')
            threat_stats[level] = threat_stats.get(level, 0) + 1
        
        # 统计漏洞类型
        vuln_types = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'other')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        summary = {
            'report_type': 'summary',
            'device_id': device_data.get('device_id', 'unknown'),
            'scan_time': device_data.get('scan_time', datetime.now().isoformat()),
            'overall_risk_score': device_data.get('risk_score', 0.0),
            'threat_statistics': threat_stats,
            'vulnerability_types': vuln_types,
            'total_threats': len(threats),
            'total_vulnerabilities': len(vulnerabilities),
            'recommendations_count': len(threats) + len(vulnerabilities),
            'security_level': self._calculate_security_level(device_data.get('risk_score', 0.0))
        }
        
        return summary
    
    def _generate_detailed_report(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成详细报告"""
        summary = self._generate_summary_report(device_data)
        
        detailed = {
            **summary,
            'report_type': 'detailed',
            'threats_detail': device_data.get('threats', []),
            'vulnerabilities_detail': device_data.get('vulnerabilities', []),
            'system_info': device_data.get('system_info', {}),
            'scan_results': device_data.get('scan_results', {}),
            'repair_history': device_data.get('repair_history', [])
        }
        
        return detailed
    
    def _generate_compliance_report(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成合规报告"""
        compliance_checks = self._perform_compliance_checks(device_data)
        
        report = {
            'report_type': 'compliance',
            'device_id': device_data.get('device_id', 'unknown'),
            'compliance_score': compliance_checks.get('score', 0),
            'passed_checks': compliance_checks.get('passed', 0),
            'failed_checks': compliance_checks.get('failed', 0),
            'compliance_items': compliance_checks.get('items', []),
            'recommendations': compliance_checks.get('recommendations', [])
        }
        
        return report
    
    def _perform_compliance_checks(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行合规检查"""
        checks = [
            {'name': '屏幕锁定', 'required': True, 'status': 'unknown'},
            {'name': '应用验证', 'required': True, 'status': 'unknown'}, 
            {'name': '未知来源', 'required': False, 'status': 'unknown'},
            {'name': '设备加密', 'required': True, 'status': 'unknown'},
            {'name': 'USB调试', 'required': False, 'status': 'unknown'}
        ]
        
        passed = sum(1 for check in checks if check['status'] == 'passed')
        failed = len(checks) - passed
        score = (passed / len(checks)) * 100 if checks else 0
        
        return {
            'score': score,
            'passed': passed,
            'failed': failed,
            'items': checks,
            'recommendations': ['启用屏幕锁定', '开启设备加密', '禁用USB调试']
        }
    
    def _calculate_security_level(self, risk_score: float) -> str:
        """计算安全级别"""
        if risk_score >= 0.8:
            return 'CRITICAL'
        elif risk_score >= 0.6:
            return 'HIGH'
        elif risk_score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'