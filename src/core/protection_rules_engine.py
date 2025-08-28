#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
保护规则引擎 - 提供规则配置、触发条件、自动响应
"""

import json
import re
import time
from typing import List, Dict, Optional, Any, Callable, Union
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import sqlite3

from ..utils.logger import LoggerMixin
from .real_time_protection import SecurityEvent, EventType, ActionType, ProtectionRule, ThreatLevel


class RuleType(Enum):
    """规则类型"""
    WHITELIST = "WHITELIST"      # 白名单规则
    BLACKLIST = "BLACKLIST"      # 黑名单规则
    BEHAVIOR = "BEHAVIOR"        # 行为规则
    CONTENT = "CONTENT"          # 内容规则
    NETWORK = "NETWORK"          # 网络规则
    CUSTOM = "CUSTOM"            # 自定义规则


class ConditionOperator(Enum):
    """条件操作符"""
    EQUALS = "EQUALS"            # 等于
    NOT_EQUALS = "NOT_EQUALS"    # 不等于
    CONTAINS = "CONTAINS"        # 包含
    NOT_CONTAINS = "NOT_CONTAINS" # 不包含
    REGEX = "REGEX"              # 正则匹配
    GREATER_THAN = "GREATER_THAN" # 大于
    LESS_THAN = "LESS_THAN"      # 小于
    IN_LIST = "IN_LIST"          # 在列表中
    NOT_IN_LIST = "NOT_IN_LIST"  # 不在列表中


@dataclass
class RuleCondition:
    """规则条件"""
    field: str                   # 字段名
    operator: ConditionOperator  # 操作符
    value: Any                   # 比较值
    case_sensitive: bool = False # 是否区分大小写


@dataclass
class RuleAction:
    """规则动作"""
    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)
    delay_seconds: int = 0       # 延迟执行秒数
    retry_count: int = 0         # 重试次数


@dataclass
class AdvancedProtectionRule:
    """高级保护规则"""
    rule_id: str
    name: str
    description: str
    rule_type: RuleType
    event_types: List[EventType]
    conditions: List[RuleCondition]
    actions: List[RuleAction]
    enabled: bool = True
    priority: int = 50
    created_time: datetime = field(default_factory=datetime.now)
    modified_time: datetime = field(default_factory=datetime.now)
    execution_count: int = 0
    last_execution: Optional[datetime] = None
    # 规则限制
    max_executions_per_hour: int = 0  # 每小时最大执行次数，0为无限制
    cooldown_seconds: int = 0         # 冷却时间


@dataclass
class RuleExecutionResult:
    """规则执行结果"""
    rule_id: str
    success: bool
    execution_time: datetime
    actions_executed: List[str]
    error_message: Optional[str] = None
    processing_time_ms: int = 0


class RuleEngine(LoggerMixin):
    """规则引擎核心"""
    
    def __init__(self, rules_db_path: str = "data/protection_rules.db"):
        self.rules_db_path = rules_db_path
        self.rules: Dict[str, AdvancedProtectionRule] = {}
        self.rule_cache: Dict[str, List[AdvancedProtectionRule]] = {}
        
        # 执行历史
        self.execution_history: List[RuleExecutionResult] = []
        
        # 统计信息
        self.stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'rules_loaded': 0
        }
        
        self._init_database()
        self._load_rules()
    
    def _init_database(self):
        """初始化数据库"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS protection_rules (
                        rule_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        rule_type TEXT NOT NULL,
                        event_types TEXT NOT NULL,
                        conditions TEXT NOT NULL,
                        actions TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        priority INTEGER DEFAULT 50,
                        created_time TEXT,
                        modified_time TEXT,
                        execution_count INTEGER DEFAULT 0,
                        last_execution TEXT,
                        max_executions_per_hour INTEGER DEFAULT 0,
                        cooldown_seconds INTEGER DEFAULT 0
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS rule_executions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        execution_time TEXT NOT NULL,
                        actions_executed TEXT,
                        error_message TEXT,
                        processing_time_ms INTEGER,
                        FOREIGN KEY (rule_id) REFERENCES protection_rules (rule_id)
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_rule_type ON protection_rules(rule_type);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_rule_priority ON protection_rules(priority);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_execution_time ON rule_executions(execution_time);
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化规则数据库失败: {e}")
    
    def _load_rules(self):
        """从数据库加载规则"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM protection_rules')
                
                for row in cursor:
                    rule = self._row_to_rule(row)
                    self.rules[rule.rule_id] = rule
                
                self.stats['rules_loaded'] = len(self.rules)
                self.logger.info(f"加载保护规则: {len(self.rules)} 条")
                
        except Exception as e:
            self.logger.error(f"加载规则失败: {e}")
    
    def _row_to_rule(self, row: sqlite3.Row) -> AdvancedProtectionRule:
        """数据库行转换为规则对象"""
        return AdvancedProtectionRule(
            rule_id=row['rule_id'],
            name=row['name'],
            description=row['description'],
            rule_type=RuleType(row['rule_type']),
            event_types=[EventType(et) for et in json.loads(row['event_types'])],
            conditions=[self._dict_to_condition(c) for c in json.loads(row['conditions'])],
            actions=[self._dict_to_action(a) for a in json.loads(row['actions'])],
            enabled=bool(row['enabled']),
            priority=row['priority'],
            created_time=datetime.fromisoformat(row['created_time']) if row['created_time'] else datetime.now(),
            modified_time=datetime.fromisoformat(row['modified_time']) if row['modified_time'] else datetime.now(),
            execution_count=row['execution_count'],
            last_execution=datetime.fromisoformat(row['last_execution']) if row['last_execution'] else None,
            max_executions_per_hour=row['max_executions_per_hour'],
            cooldown_seconds=row['cooldown_seconds']
        )
    
    def _dict_to_condition(self, condition_dict: Dict) -> RuleCondition:
        """字典转换为条件对象"""
        return RuleCondition(
            field=condition_dict['field'],
            operator=ConditionOperator(condition_dict['operator']),
            value=condition_dict['value'],
            case_sensitive=condition_dict.get('case_sensitive', False)
        )
    
    def _dict_to_action(self, action_dict: Dict) -> RuleAction:
        """字典转换为动作对象"""
        return RuleAction(
            action_type=ActionType(action_dict['action_type']),
            parameters=action_dict.get('parameters', {}),
            delay_seconds=action_dict.get('delay_seconds', 0),
            retry_count=action_dict.get('retry_count', 0)
        )
    
    def add_rule(self, rule: AdvancedProtectionRule) -> bool:
        """添加规则"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO protection_rules
                    (rule_id, name, description, rule_type, event_types, conditions, actions,
                     enabled, priority, created_time, modified_time, execution_count,
                     last_execution, max_executions_per_hour, cooldown_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule.rule_id,
                    rule.name,
                    rule.description,
                    rule.rule_type.value,
                    json.dumps([et.value for et in rule.event_types]),
                    json.dumps([asdict(c) for c in rule.conditions]),
                    json.dumps([asdict(a) for a in rule.actions]),
                    rule.enabled,
                    rule.priority,
                    rule.created_time.isoformat(),
                    rule.modified_time.isoformat(),
                    rule.execution_count,
                    rule.last_execution.isoformat() if rule.last_execution else None,
                    rule.max_executions_per_hour,
                    rule.cooldown_seconds
                ))
                
                conn.commit()
            
            self.rules[rule.rule_id] = rule
            self._clear_cache()
            self.logger.info(f"添加规则: {rule.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加规则失败: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """删除规则"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.execute('DELETE FROM protection_rules WHERE rule_id = ?', (rule_id,))
                conn.commit()
            
            if rule_id in self.rules:
                del self.rules[rule_id]
                self._clear_cache()
                self.logger.info(f"删除规则: {rule_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"删除规则失败: {e}")
            return False
    
    def update_rule(self, rule: AdvancedProtectionRule) -> bool:
        """更新规则"""
        rule.modified_time = datetime.now()
        return self.add_rule(rule)
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """启用/禁用规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled
            self.rules[rule_id].modified_time = datetime.now()
            return self.update_rule(self.rules[rule_id])
        return False
    
    def get_matching_rules(self, event: SecurityEvent) -> List[AdvancedProtectionRule]:
        """获取匹配的规则"""
        cache_key = f"{event.event_type.value}_{event.threat_level.value}"
        
        if cache_key not in self.rule_cache:
            matching_rules = []
            
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                
                if event.event_type in rule.event_types:
                    if self._check_rule_conditions(rule, event):
                        if self._check_rule_limits(rule):
                            matching_rules.append(rule)
            
            # 按优先级排序
            matching_rules.sort(key=lambda r: r.priority, reverse=True)
            self.rule_cache[cache_key] = matching_rules
        
        return self.rule_cache[cache_key]
    
    def _check_rule_conditions(self, rule: AdvancedProtectionRule, event: SecurityEvent) -> bool:
        """检查规则条件"""
        try:
            for condition in rule.conditions:
                if not self._evaluate_condition(condition, event):
                    return False
            return True
            
        except Exception as e:
            self.logger.error(f"检查规则条件失败: {e}")
            return False
    
    def _evaluate_condition(self, condition: RuleCondition, event: SecurityEvent) -> bool:
        """评估单个条件"""
        try:
            # 获取事件字段值
            field_value = self._get_event_field_value(event, condition.field)
            
            if field_value is None:
                return False
            
            # 处理大小写敏感性
            if isinstance(field_value, str) and not condition.case_sensitive:
                field_value = field_value.lower()
                if isinstance(condition.value, str):
                    condition.value = condition.value.lower()
            
            # 根据操作符进行比较
            if condition.operator == ConditionOperator.EQUALS:
                return field_value == condition.value
            
            elif condition.operator == ConditionOperator.NOT_EQUALS:
                return field_value != condition.value
            
            elif condition.operator == ConditionOperator.CONTAINS:
                return str(condition.value) in str(field_value)
            
            elif condition.operator == ConditionOperator.NOT_CONTAINS:
                return str(condition.value) not in str(field_value)
            
            elif condition.operator == ConditionOperator.REGEX:
                pattern = condition.value
                flags = 0 if condition.case_sensitive else re.IGNORECASE
                return bool(re.search(pattern, str(field_value), flags))
            
            elif condition.operator == ConditionOperator.GREATER_THAN:
                return float(field_value) > float(condition.value)
            
            elif condition.operator == ConditionOperator.LESS_THAN:
                return float(field_value) < float(condition.value)
            
            elif condition.operator == ConditionOperator.IN_LIST:
                return field_value in condition.value
            
            elif condition.operator == ConditionOperator.NOT_IN_LIST:
                return field_value not in condition.value
            
            return False
            
        except Exception as e:
            self.logger.error(f"评估条件失败: {e}")
            return False
    
    def _get_event_field_value(self, event: SecurityEvent, field: str) -> Any:
        """获取事件字段值"""
        try:
            # 支持点号分隔的字段路径
            parts = field.split('.')
            value = event
            
            for part in parts:
                if hasattr(value, part):
                    value = getattr(value, part)
                elif isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return None
            
            # 特殊处理枚举类型
            if hasattr(value, 'value'):
                return value.value
            
            return value
            
        except Exception as e:
            self.logger.error(f"获取事件字段值失败: {e}")
            return None
    
    def _check_rule_limits(self, rule: AdvancedProtectionRule) -> bool:
        """检查规则限制"""
        try:
            current_time = datetime.now()
            
            # 检查冷却时间
            if rule.cooldown_seconds > 0 and rule.last_execution:
                time_since_last = (current_time - rule.last_execution).total_seconds()
                if time_since_last < rule.cooldown_seconds:
                    return False
            
            # 检查每小时执行次数限制
            if rule.max_executions_per_hour > 0:
                hour_ago = current_time - timedelta(hours=1)
                recent_executions = self._count_recent_executions(rule.rule_id, hour_ago)
                if recent_executions >= rule.max_executions_per_hour:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"检查规则限制失败: {e}")
            return False
    
    def _count_recent_executions(self, rule_id: str, since_time: datetime) -> int:
        """统计最近的执行次数"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM rule_executions 
                    WHERE rule_id = ? AND execution_time > ?
                ''', (rule_id, since_time.isoformat()))
                
                return cursor.fetchone()[0]
                
        except Exception as e:
            self.logger.error(f"统计执行次数失败: {e}")
            return 0
    
    def execute_rule(self, rule: AdvancedProtectionRule, event: SecurityEvent) -> RuleExecutionResult:
        """执行规则"""
        start_time = time.time()
        execution_time = datetime.now()
        actions_executed = []
        error_message = None
        success = True
        
        try:
            self.logger.info(f"执行规则: {rule.name} (ID: {rule.rule_id})")
            
            # 执行所有动作
            for action in rule.actions:
                try:
                    # 延迟执行
                    if action.delay_seconds > 0:
                        time.sleep(action.delay_seconds)
                    
                    # 执行动作
                    action_success = self._execute_action(action, event)
                    
                    if action_success:
                        actions_executed.append(action.action_type.value)
                    else:
                        # 重试机制
                        for retry in range(action.retry_count):
                            self.logger.info(f"重试动作 {action.action_type.value} ({retry + 1}/{action.retry_count})")
                            time.sleep(1)  # 重试间隔
                            if self._execute_action(action, event):
                                actions_executed.append(f"{action.action_type.value}_retry_{retry + 1}")
                                action_success = True
                                break
                        
                        if not action_success:
                            error_message = f"动作执行失败: {action.action_type.value}"
                            success = False
                
                except Exception as e:
                    error_message = f"执行动作异常: {str(e)}"
                    success = False
                    self.logger.error(error_message)
            
            # 更新规则执行统计
            rule.execution_count += 1
            rule.last_execution = execution_time
            self._update_rule_stats(rule)
            
        except Exception as e:
            error_message = f"规则执行异常: {str(e)}"
            success = False
            self.logger.error(error_message)
        
        finally:
            processing_time = int((time.time() - start_time) * 1000)
            
            # 创建执行结果
            result = RuleExecutionResult(
                rule_id=rule.rule_id,
                success=success,
                execution_time=execution_time,
                actions_executed=actions_executed,
                error_message=error_message,
                processing_time_ms=processing_time
            )
            
            # 记录执行历史
            self._record_execution(result)
            
            # 更新统计
            self.stats['total_executions'] += 1
            if success:
                self.stats['successful_executions'] += 1
            else:
                self.stats['failed_executions'] += 1
            
            return result
    
    def _execute_action(self, action: RuleAction, event: SecurityEvent) -> bool:
        """执行具体动作"""
        try:
            # 这里可以扩展具体的动作执行逻辑
            if action.action_type == ActionType.LOG:
                self.logger.info(f"规则动作日志: {event.description}")
                return True
            
            elif action.action_type == ActionType.ALERT:
                self.logger.warning(f"规则动作警报: {event.description}")
                return True
            
            elif action.action_type == ActionType.BLOCK:
                self.logger.info(f"规则动作阻止: {event.source}")
                return True
            
            elif action.action_type == ActionType.QUARANTINE:
                self.logger.info(f"规则动作隔离: {event.source}")
                return True
            
            else:
                self.logger.warning(f"未知动作类型: {action.action_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"执行动作失败: {e}")
            return False
    
    def _update_rule_stats(self, rule: AdvancedProtectionRule):
        """更新规则统计"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.execute('''
                    UPDATE protection_rules 
                    SET execution_count = ?, last_execution = ?
                    WHERE rule_id = ?
                ''', (rule.execution_count, rule.last_execution.isoformat(), rule.rule_id))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"更新规则统计失败: {e}")
    
    def _record_execution(self, result: RuleExecutionResult):
        """记录执行历史"""
        try:
            with sqlite3.connect(self.rules_db_path) as conn:
                conn.execute('''
                    INSERT INTO rule_executions
                    (rule_id, success, execution_time, actions_executed, error_message, processing_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    result.rule_id,
                    result.success,
                    result.execution_time.isoformat(),
                    json.dumps(result.actions_executed),
                    result.error_message,
                    result.processing_time_ms
                ))
                conn.commit()
            
            self.execution_history.append(result)
            
            # 限制内存中的历史记录数量
            if len(self.execution_history) > 1000:
                self.execution_history = self.execution_history[-500:]
                
        except Exception as e:
            self.logger.error(f"记录执行历史失败: {e}")
    
    def _clear_cache(self):
        """清除规则缓存"""
        self.rule_cache.clear()
    
    def get_rules(self, rule_type: Optional[RuleType] = None, enabled_only: bool = False) -> List[AdvancedProtectionRule]:
        """获取规则列表"""
        rules = list(self.rules.values())
        
        if rule_type:
            rules = [r for r in rules if r.rule_type == rule_type]
        
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        
        return rules
    
    def get_rule(self, rule_id: str) -> Optional[AdvancedProtectionRule]:
        """获取指定规则"""
        return self.rules.get(rule_id)
    
    def get_execution_history(self, rule_id: Optional[str] = None, limit: int = 100) -> List[RuleExecutionResult]:
        """获取执行历史"""
        history = self.execution_history
        
        if rule_id:
            history = [r for r in history if r.rule_id == rule_id]
        
        return history[-limit:] if history else []
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self.stats.copy()
        stats.update({
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules.values() if r.enabled]),
            'disabled_rules': len([r for r in self.rules.values() if not r.enabled]),
            'rules_by_type': {},
            'execution_success_rate': 0.0
        })
        
        # 按类型统计规则
        for rule in self.rules.values():
            rule_type = rule.rule_type.value
            if rule_type not in stats['rules_by_type']:
                stats['rules_by_type'][rule_type] = 0
            stats['rules_by_type'][rule_type] += 1
        
        # 计算执行成功率
        if stats['total_executions'] > 0:
            stats['execution_success_rate'] = stats['successful_executions'] / stats['total_executions']
        
        return stats


class ProtectionRuleManager(LoggerMixin):
    """保护规则管理器"""
    
    def __init__(self):
        self.rule_engine = RuleEngine()
        self._load_default_rules()
    
    def _load_default_rules(self):
        """加载默认规则"""
        default_rules = [
            # 恶意文件阻止规则
            AdvancedProtectionRule(
                rule_id="block_critical_malware",
                name="阻止严重恶意软件",
                description="自动阻止严重威胁级别的恶意软件",
                rule_type=RuleType.BLACKLIST,
                event_types=[EventType.FILE_CREATED, EventType.FILE_MODIFIED],
                conditions=[
                    RuleCondition("threat_level", ConditionOperator.EQUALS, "CRITICAL")
                ],
                actions=[
                    RuleAction(ActionType.QUARANTINE),
                    RuleAction(ActionType.ALERT)
                ],
                priority=95
            ),
            
            # 可疑进程监控规则
            AdvancedProtectionRule(
                rule_id="monitor_suspicious_processes",
                name="监控可疑进程",
                description="监控包含可疑关键词的进程",
                rule_type=RuleType.BEHAVIOR,
                event_types=[EventType.PROCESS_STARTED],
                conditions=[
                    RuleCondition("source", ConditionOperator.REGEX, r".*(fake|trojan|malware).*")
                ],
                actions=[
                    RuleAction(ActionType.ALERT),
                    RuleAction(ActionType.LOG)
                ],
                priority=80
            ),
            
            # 网络连接限制规则
            AdvancedProtectionRule(
                rule_id="block_malicious_connections",
                name="阻止恶意网络连接",
                description="阻止连接到已知恶意IP地址",
                rule_type=RuleType.NETWORK,
                event_types=[EventType.NETWORK_CONNECTION],
                conditions=[
                    RuleCondition("threat_level", ConditionOperator.IN_LIST, ["HIGH", "CRITICAL"])
                ],
                actions=[
                    RuleAction(ActionType.BLOCK),
                    RuleAction(ActionType.LOG)
                ],
                priority=90
            )
        ]
        
        for rule in default_rules:
            if not self.rule_engine.get_rule(rule.rule_id):
                self.rule_engine.add_rule(rule)
    
    def process_event(self, event: SecurityEvent) -> List[RuleExecutionResult]:
        """处理安全事件"""
        results = []
        
        try:
            # 获取匹配的规则
            matching_rules = self.rule_engine.get_matching_rules(event)
            
            # 执行规则
            for rule in matching_rules:
                result = self.rule_engine.execute_rule(rule, event)
                results.append(result)
            
        except Exception as e:
            self.logger.error(f"处理事件失败: {e}")
        
        return results
    
    def add_custom_rule(self, rule: AdvancedProtectionRule) -> bool:
        """添加自定义规则"""
        return self.rule_engine.add_rule(rule)
    
    def get_rule_engine(self) -> RuleEngine:
        """获取规则引擎"""
        return self.rule_engine