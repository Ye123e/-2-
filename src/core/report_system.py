#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告系统 - 扫描报告、修复报告、统计分析、导出功能
"""

import json
import csv
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import asdict
from enum import Enum

from ..utils.logger import LoggerMixin
from ..models import *
from .database_manager import DatabaseManager


class ReportFormat(Enum):
    """报告格式"""
    JSON = "JSON"
    CSV = "CSV"
    HTML = "HTML"
    PDF = "PDF"
    XML = "XML"


class ReportType(Enum):
    """报告类型"""
    SCAN_SUMMARY = "SCAN_SUMMARY"
    SECURITY_ANALYSIS = "SECURITY_ANALYSIS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    VULNERABILITY_ASSESSMENT = "VULNERABILITY_ASSESSMENT"
    PERFORMANCE_METRICS = "PERFORMANCE_METRICS"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"


class ReportGenerator(LoggerMixin):
    """报告生成器"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.report_templates = {
            ReportType.SCAN_SUMMARY: self._generate_scan_summary,
            ReportType.SECURITY_ANALYSIS: self._generate_security_analysis,
            ReportType.THREAT_INTELLIGENCE: self._generate_threat_intelligence,
            ReportType.VULNERABILITY_ASSESSMENT: self._generate_vulnerability_assessment,
            ReportType.PERFORMANCE_METRICS: self._generate_performance_metrics,
            ReportType.COMPLIANCE_CHECK: self._generate_compliance_check
        }
    
    def generate_report(self, report_type: ReportType, 
                       device_id: str = None, 
                       time_range: Dict[str, datetime] = None,
                       parameters: Dict[str, Any] = None) -> SystemReport:
        """生成报告"""
        try:
            if parameters is None:
                parameters = {}
            
            if time_range is None:
                time_range = {
                    'start': datetime.now() - timedelta(days=30),
                    'end': datetime.now()
                }
            
            # 调用对应的报告生成方法
            generator_func = self.report_templates.get(report_type)
            if not generator_func:
                raise ValueError(f"不支持的报告类型: {report_type}")
            
            report_data = generator_func(device_id, time_range, parameters)
            
            # 创建系统报告对象
            report = SystemReport(
                report_id=f"report_{int(datetime.now().timestamp())}",
                device_id=device_id or "all_devices",
                report_type=report_type.value,
                generation_time=datetime.now(),
                data=report_data,
                summary=self._generate_summary(report_type, report_data),
                recommendations=self._generate_recommendations(report_type, report_data),
                export_formats=[ReportFormat.JSON.value, ReportFormat.HTML.value]
            )
            
            self.logger.info(f"生成报告完成: {report_type.value}")
            return report
            
        except Exception as e:
            self.logger.error(f"生成报告失败: {e}")
            raise
    
    def _generate_scan_summary(self, device_id: str, time_range: Dict[str, datetime], 
                              parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成扫描摘要报告"""
        data = {
            'scan_overview': {},
            'threat_summary': {},
            'time_analysis': {},
            'device_breakdown': {}
        }
        
        try:
            # 获取扫描结果
            scan_results = self.db_manager.get_scan_results(device_id, limit=1000)
            
            # 过滤时间范围
            filtered_scans = [
                scan for scan in scan_results 
                if time_range['start'] <= scan.start_time <= time_range['end']
            ]
            
            # 扫描概览
            data['scan_overview'] = {
                'total_scans': len(filtered_scans),
                'completed_scans': len([s for s in filtered_scans if s.is_completed]),
                'total_files_scanned': sum(s.total_files_scanned for s in filtered_scans),
                'total_threats_found': sum(s.threats_found for s in filtered_scans),
                'total_vulnerabilities_found': sum(s.vulnerabilities_found for s in filtered_scans)
            }
            
            # 威胁摘要
            threat_types = {}
            threat_levels = {}
            
            for scan in filtered_scans:
                for malware in scan.malware_list:
                    threat_type = malware.threat_type.value
                    threat_level = malware.threat_level.value
                    
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                    threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
            
            data['threat_summary'] = {
                'by_type': threat_types,
                'by_level': threat_levels
            }
            
            # 时间分析
            daily_stats = {}
            for scan in filtered_scans:
                date_key = scan.start_time.strftime('%Y-%m-%d')
                if date_key not in daily_stats:
                    daily_stats[date_key] = {
                        'scans': 0,
                        'threats': 0,
                        'vulnerabilities': 0
                    }
                
                daily_stats[date_key]['scans'] += 1
                daily_stats[date_key]['threats'] += scan.threats_found
                daily_stats[date_key]['vulnerabilities'] += scan.vulnerabilities_found
            
            data['time_analysis'] = daily_stats
            
            # 设备分解（如果查询所有设备）
            if not device_id:
                device_stats = {}
                for scan in filtered_scans:
                    device = scan.device_id
                    if device not in device_stats:
                        device_stats[device] = {
                            'scans': 0,
                            'threats': 0,
                            'vulnerabilities': 0
                        }
                    
                    device_stats[device]['scans'] += 1
                    device_stats[device]['threats'] += scan.threats_found
                    device_stats[device]['vulnerabilities'] += scan.vulnerabilities_found
                
                data['device_breakdown'] = device_stats
            
        except Exception as e:
            self.logger.error(f"生成扫描摘要失败: {e}")
        
        return data
    
    def _generate_security_analysis(self, device_id: str, time_range: Dict[str, datetime], 
                                   parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成安全分析报告"""
        data = {
            'security_events': {},
            'risk_assessment': {},
            'attack_patterns': {},
            'protection_effectiveness': {}
        }
        
        try:
            # 获取安全事件
            security_events = self.db_manager.get_security_events(device_id, limit=10000)
            
            # 过滤时间范围
            filtered_events = [
                event for event in security_events 
                if time_range['start'] <= event.timestamp <= time_range['end']
            ]
            
            # 安全事件分析
            event_types = {}
            threat_levels = {}
            hourly_distribution = {}
            
            for event in filtered_events:
                # 事件类型统计
                event_type = event.event_type
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                # 威胁级别统计
                threat_level = event.threat_level.value
                threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
                
                # 小时分布
                hour = event.timestamp.hour
                hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
            
            data['security_events'] = {
                'total_events': len(filtered_events),
                'by_type': event_types,
                'by_threat_level': threat_levels,
                'hourly_distribution': hourly_distribution
            }
            
            # 风险评估
            high_risk_events = [e for e in filtered_events if e.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
            
            data['risk_assessment'] = {
                'high_risk_events': len(high_risk_events),
                'risk_score': min(100, len(high_risk_events) * 5),  # 简化的风险评分
                'most_common_threats': sorted(threat_levels.items(), key=lambda x: x[1], reverse=True)[:5]
            }
            
        except Exception as e:
            self.logger.error(f"生成安全分析失败: {e}")
        
        return data
    
    def _generate_threat_intelligence(self, device_id: str, time_range: Dict[str, datetime], 
                                     parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成威胁情报报告"""
        data = {
            'emerging_threats': {},
            'attack_trends': {},
            'ioc_analysis': {},
            'attribution': {}
        }
        
        # 这里可以集成外部威胁情报源
        # 目前使用本地数据进行分析
        
        return data
    
    def _generate_vulnerability_assessment(self, device_id: str, time_range: Dict[str, datetime], 
                                          parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成漏洞评估报告"""
        data = {
            'vulnerability_summary': {},
            'cvss_analysis': {},
            'patch_status': {},
            'exposure_risk': {}
        }
        
        # 实现漏洞评估逻辑
        
        return data
    
    def _generate_performance_metrics(self, device_id: str, time_range: Dict[str, datetime], 
                                     parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成性能指标报告"""
        data = {
            'scan_performance': {},
            'system_resources': {},
            'response_times': {},
            'throughput': {}
        }
        
        # 实现性能指标分析
        
        return data
    
    def _generate_compliance_check(self, device_id: str, time_range: Dict[str, datetime], 
                                  parameters: Dict[str, Any]) -> Dict[str, Any]:
        """生成合规检查报告"""
        data = {
            'compliance_status': {},
            'policy_violations': {},
            'remediation_actions': {},
            'certification_readiness': {}
        }
        
        # 实现合规检查逻辑
        
        return data
    
    def _generate_summary(self, report_type: ReportType, data: Dict[str, Any]) -> str:
        """生成报告摘要"""
        if report_type == ReportType.SCAN_SUMMARY:
            overview = data.get('scan_overview', {})
            total_scans = overview.get('total_scans', 0)
            total_threats = overview.get('total_threats_found', 0)
            return f"扫描摘要：共执行{total_scans}次扫描，发现{total_threats}个威胁"
        
        elif report_type == ReportType.SECURITY_ANALYSIS:
            events = data.get('security_events', {})
            total_events = events.get('total_events', 0)
            risk = data.get('risk_assessment', {}).get('risk_score', 0)
            return f"安全分析：记录{total_events}个安全事件，当前风险评分{risk}"
        
        return f"生成了{report_type.value}报告"
    
    def _generate_recommendations(self, report_type: ReportType, data: Dict[str, Any]) -> List[str]:
        """生成建议"""
        recommendations = []
        
        if report_type == ReportType.SCAN_SUMMARY:
            overview = data.get('scan_overview', {})
            threats = overview.get('total_threats_found', 0)
            
            if threats > 0:
                recommendations.append("发现威胁，建议立即进行清理")
                recommendations.append("加强实时防护设置")
            else:
                recommendations.append("系统安全状态良好")
            
            recommendations.append("建议定期进行全面扫描")
        
        elif report_type == ReportType.SECURITY_ANALYSIS:
            risk_score = data.get('risk_assessment', {}).get('risk_score', 0)
            
            if risk_score > 50:
                recommendations.append("检测到高风险活动，建议立即调查")
                recommendations.append("强化安全监控规则")
            
            recommendations.append("定期审查安全事件")
        
        return recommendations


class ReportExporter(LoggerMixin):
    """报告导出器"""
    
    def __init__(self):
        self.export_handlers = {
            ReportFormat.JSON: self._export_json,
            ReportFormat.CSV: self._export_csv,
            ReportFormat.HTML: self._export_html,
            ReportFormat.XML: self._export_xml
        }
    
    def export_report(self, report: SystemReport, format_type: ReportFormat, 
                     output_path: str) -> bool:
        """导出报告"""
        try:
            export_handler = self.export_handlers.get(format_type)
            if not export_handler:
                raise ValueError(f"不支持的导出格式: {format_type}")
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            export_handler(report, output_file)
            
            self.logger.info(f"报告导出成功: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"报告导出失败: {e}")
            return False
    
    def _export_json(self, report: SystemReport, output_file: Path):
        """导出JSON格式"""
        report_dict = report.to_dict()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False, default=str)
    
    def _export_csv(self, report: SystemReport, output_file: Path):
        """导出CSV格式"""
        # 简化的CSV导出，主要导出摘要信息
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # 写入报告基本信息
            writer.writerow(['字段', '值'])
            writer.writerow(['报告ID', report.report_id])
            writer.writerow(['设备ID', report.device_id])
            writer.writerow(['报告类型', report.report_type])
            writer.writerow(['生成时间', report.generation_time.isoformat()])
            writer.writerow(['摘要', report.summary])
            
            # 写入建议
            writer.writerow([])
            writer.writerow(['建议'])
            for recommendation in report.recommendations:
                writer.writerow([recommendation])
    
    def _export_html(self, report: SystemReport, output_file: Path):
        """导出HTML格式"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>安全报告 - {report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 20px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .data-table {{ border-collapse: collapse; width: 100%; }}
        .data-table th, .data-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .data-table th {{ background-color: #f2f2f2; }}
        .recommendations {{ background-color: #e7f3ff; padding: 15px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>安全报告</h1>
        <p><strong>报告ID:</strong> {report_id}</p>
        <p><strong>设备ID:</strong> {device_id}</p>
        <p><strong>报告类型:</strong> {report_type}</p>
        <p><strong>生成时间:</strong> {generation_time}</p>
    </div>
    
    <div class="section">
        <h2>摘要</h2>
        <p>{summary}</p>
    </div>
    
    <div class="section">
        <h2>详细数据</h2>
        <pre>{data}</pre>
    </div>
    
    <div class="section recommendations">
        <h2>建议</h2>
        <ul>
        {recommendations_html}
        </ul>
    </div>
</body>
</html>
        """
        
        recommendations_html = ''.join([f'<li>{rec}</li>' for rec in report.recommendations])
        
        html_content = html_template.format(
            report_id=report.report_id,
            device_id=report.device_id,
            report_type=report.report_type,
            generation_time=report.generation_time.strftime('%Y-%m-%d %H:%M:%S'),
            summary=report.summary,
            data=json.dumps(report.data, indent=2, ensure_ascii=False, default=str),
            recommendations_html=recommendations_html
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _export_xml(self, report: SystemReport, output_file: Path):
        """导出XML格式"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element('SecurityReport')
        
        # 基本信息
        ET.SubElement(root, 'ReportId').text = report.report_id
        ET.SubElement(root, 'DeviceId').text = report.device_id
        ET.SubElement(root, 'ReportType').text = report.report_type
        ET.SubElement(root, 'GenerationTime').text = report.generation_time.isoformat()
        ET.SubElement(root, 'Summary').text = report.summary
        
        # 数据
        data_element = ET.SubElement(root, 'Data')
        data_element.text = json.dumps(report.data, default=str)
        
        # 建议
        recommendations_element = ET.SubElement(root, 'Recommendations')
        for rec in report.recommendations:
            ET.SubElement(recommendations_element, 'Recommendation').text = rec
        
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)


class ReportScheduler(LoggerMixin):
    """报告调度器"""
    
    def __init__(self, report_generator: ReportGenerator, report_exporter: ReportExporter):
        self.report_generator = report_generator
        self.report_exporter = report_exporter
        self.scheduled_reports: List[Dict[str, Any]] = []
    
    def schedule_report(self, report_type: ReportType, frequency: str, 
                       export_format: ReportFormat, output_dir: str,
                       device_id: str = None, parameters: Dict[str, Any] = None):
        """调度定期报告"""
        schedule_config = {
            'report_type': report_type,
            'frequency': frequency,  # daily, weekly, monthly
            'export_format': export_format,
            'output_dir': output_dir,
            'device_id': device_id,
            'parameters': parameters or {},
            'last_run': None,
            'next_run': self._calculate_next_run(frequency)
        }
        
        self.scheduled_reports.append(schedule_config)
        self.logger.info(f"已调度{frequency}报告: {report_type.value}")
    
    def _calculate_next_run(self, frequency: str) -> datetime:
        """计算下次运行时间"""
        now = datetime.now()
        
        if frequency == 'daily':
            return now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        elif frequency == 'weekly':
            days_ahead = 7 - now.weekday()
            return now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)
        elif frequency == 'monthly':
            if now.month == 12:
                return now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            else:
                return now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
        
        return now + timedelta(days=1)
    
    def check_and_run_scheduled_reports(self):
        """检查并运行调度的报告"""
        current_time = datetime.now()
        
        for schedule in self.scheduled_reports:
            if current_time >= schedule['next_run']:
                try:
                    self._execute_scheduled_report(schedule)
                    schedule['last_run'] = current_time
                    schedule['next_run'] = self._calculate_next_run(schedule['frequency'])
                    
                except Exception as e:
                    self.logger.error(f"执行调度报告失败: {e}")
    
    def _execute_scheduled_report(self, schedule: Dict[str, Any]):
        """执行调度的报告"""
        # 生成报告
        report = self.report_generator.generate_report(
            schedule['report_type'],
            schedule['device_id'],
            parameters=schedule['parameters']
        )
        
        # 导出报告
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{schedule['report_type'].value}_{timestamp}.{schedule['export_format'].value.lower()}"
        output_path = Path(schedule['output_dir']) / filename
        
        self.report_exporter.export_report(
            report,
            schedule['export_format'],
            str(output_path)
        )


class ReportManager(LoggerMixin):
    """报告管理器主类"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.generator = ReportGenerator(db_manager)
        self.exporter = ReportExporter()
        self.scheduler = ReportScheduler(self.generator, self.exporter)
    
    def create_and_export_report(self, report_type: ReportType, 
                                export_format: ReportFormat, output_path: str,
                                device_id: str = None, 
                                time_range: Dict[str, datetime] = None,
                                parameters: Dict[str, Any] = None) -> bool:
        """创建并导出报告"""
        try:
            # 生成报告
            report = self.generator.generate_report(
                report_type, device_id, time_range, parameters
            )
            
            # 导出报告
            success = self.exporter.export_report(report, export_format, output_path)
            
            if success:
                # 保存报告记录到数据库
                self.db_manager.insert_system_report(report)
            
            return success
            
        except Exception as e:
            self.logger.error(f"创建并导出报告失败: {e}")
            return False
    
    def get_available_report_types(self) -> List[str]:
        """获取可用的报告类型"""
        return [report_type.value for report_type in ReportType]
    
    def get_supported_export_formats(self) -> List[str]:
        """获取支持的导出格式"""
        return [format_type.value for format_type in ReportFormat]