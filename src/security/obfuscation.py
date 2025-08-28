#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码混淆模块 - 提供关键算法保护、字符串加密、控制流混淆
"""

import base64
import hashlib
import random
import string
import zlib
from typing import Dict, List, Any, Optional, Callable
import secrets

from ..utils.logger import LoggerMixin


class StringObfuscator(LoggerMixin):
    """字符串混淆器"""
    
    def __init__(self, key: Optional[str] = None):
        self.key = key or secrets.token_hex(32)
        
        # 字符串映射表
        self.string_map: Dict[str, str] = {}
        self.reverse_map: Dict[str, str] = {}
        
        # 混淆计数器
        self.obfuscation_counter = 0
    
    def simple_encrypt_string(self, text: str) -> str:
        """简单字符串加密（XOR方式）"""
        try:
            # 使用XOR加密
            key_bytes = self.key.encode('utf-8')
            text_bytes = text.encode('utf-8')
            
            encrypted = bytearray()
            for i, byte in enumerate(text_bytes):
                key_byte = key_bytes[i % len(key_bytes)]
                encrypted.append(byte ^ key_byte)
            
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            self.logger.error(f"字符串加密失败: {e}")
            return text
    
    def simple_decrypt_string(self, encrypted_text: str, key: str) -> str:
        """简单字符串解密"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            key_bytes = key.encode('utf-8')
            
            decrypted = bytearray()
            for i, byte in enumerate(encrypted_bytes):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(byte ^ key_byte)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            self.logger.error(f"字符串解密失败: {e}")
            return encrypted_text
    
    def obfuscate_string(self, text: str) -> str:
        """混淆字符串（使用随机标识符替换）"""
        if text in self.string_map:
            return self.string_map[text]
        
        # 生成混淆后的标识符
        obfuscated = f"__{self._generate_random_name()}__"
        self.string_map[text] = obfuscated
        self.reverse_map[obfuscated] = text
        self.obfuscation_counter += 1
        
        return obfuscated
    
    def _generate_random_name(self) -> str:
        """生成随机名称"""
        return ''.join(random.choices(string.ascii_letters, k=8)) + str(self.obfuscation_counter)
    
    def generate_decryption_function(self) -> str:
        """生成解密函数代码"""
        function_code = f'''
def _decrypt_string(encrypted_text):
    """动态字符串解密函数"""
    import base64
    
    key = "{self.key}"
    
    try:
        encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
        key_bytes = key.encode('utf-8')
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted.append(byte ^ key_byte)
        
        return decrypted.decode('utf-8')
    except:
        return encrypted_text

# 混淆字符串映射
_STRING_MAP = {string.format_map_string}
'''
        
        # 创建字符串映射
        map_dict = {k: self.simple_encrypt_string(v) for k, v in self.reverse_map.items()}
        map_str = str(map_dict).replace("'", '"')
        
        return function_code.replace("{string.format_map_string}", map_str)


class CodeObfuscator(LoggerMixin):
    """代码混淆器"""
    
    def __init__(self):
        self.string_obfuscator = StringObfuscator()
        
        # 标识符映射
        self.identifier_map: Dict[str, str] = {}
        
        # 需要保护的关键字
        self.protected_keywords = {
            'virus', 'malware', 'trojan', 'scan', 'detect', 'threat',
            'signature', 'hash', 'encrypt', 'decrypt', 'quarantine',
            'repair', 'patch', 'vulnerability', 'exploit', 'security'
        }
        
        # 函数名混淆映射
        self.function_map: Dict[str, str] = {}
        
        # 变量名混淆映射
        self.variable_map: Dict[str, str] = {}
    
    def obfuscate_identifier(self, identifier: str, identifier_type: str = "general") -> str:
        """混淆标识符"""
        if identifier in self.identifier_map:
            return self.identifier_map[identifier]
        
        # 检查是否需要保护
        if any(keyword in identifier.lower() for keyword in self.protected_keywords):
            obfuscated = self._generate_obfuscated_name(identifier_type)
            self.identifier_map[identifier] = obfuscated
            return obfuscated
        
        return identifier
    
    def _generate_obfuscated_name(self, prefix: str = "") -> str:
        """生成混淆后的名称"""
        if prefix:
            return f"_{prefix}_{secrets.token_hex(4)}"
        return f"_{secrets.token_hex(6)}"
    
    def obfuscate_function_names(self, code: str) -> str:
        """混淆函数名"""
        import re
        
        # 匹配函数定义
        def_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        
        def replace_function(match):
            func_name = match.group(1)
            if func_name not in self.function_map:
                self.function_map[func_name] = self.obfuscate_identifier(func_name, "func")
            return f'def {self.function_map[func_name]}('
        
        # 替换函数定义
        obfuscated_code = re.sub(def_pattern, replace_function, code)
        
        # 替换函数调用
        for original, obfuscated in self.function_map.items():
            # 匹配函数调用（避免替换字符串中的内容）
            call_pattern = r'\b' + re.escape(original) + r'\s*\('
            obfuscated_code = re.sub(call_pattern, f'{obfuscated}(', obfuscated_code)
        
        return obfuscated_code
    
    def obfuscate_strings(self, code: str) -> str:
        """混淆代码中的字符串"""
        import re
        
        # 匹配字符串字面量
        string_patterns = [
            r'"([^"\\\\]|\\\\.)*"',  # 双引号字符串
            r"'([^'\\\\]|\\\\.)*'"   # 单引号字符串
        ]
        
        def replace_string(match):
            original_string = match.group(0)
            string_content = original_string[1:-1]  # 去掉引号
            
            # 检查是否包含敏感关键字
            if any(keyword in string_content.lower() for keyword in self.protected_keywords):
                encrypted = self.string_obfuscator.simple_encrypt_string(string_content)
                return f'_decrypt_string("{encrypted}")'
            
            return original_string
        
        obfuscated_code = code
        for pattern in string_patterns:
            obfuscated_code = re.sub(pattern, replace_string, obfuscated_code)
        
        return obfuscated_code
    
    def add_control_flow_obfuscation(self, code: str) -> str:
        """添加控制流混淆"""
        # 简单的控制流混淆：添加虚假分支
        
        obfuscated_lines = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            obfuscated_lines.append(line)
            
            # 在关键位置添加虚假分支
            if 'def ' in line or 'if ' in line or 'for ' in line:
                if random.random() < 0.1:  # 10%概率添加虚假分支
                    indent = len(line) - len(line.lstrip())
                    fake_condition = self._generate_fake_condition()
                    fake_line = ' ' * (indent + 4) + f"if {fake_condition}: pass  # 虚假分支"
                    obfuscated_lines.append(fake_line)
        
        return '\n'.join(obfuscated_lines)
    
    def _generate_fake_condition(self) -> str:
        """生成虚假条件"""
        conditions = [
            "random.random() < 0.001",
            "len('') > 0",
            "1 == 2",
            "False and True",
            "[] != []"
        ]
        return random.choice(conditions)
    
    def obfuscate_code(self, code: str, include_decryption: bool = True) -> str:
        """完整的代码混淆"""
        try:
            self.logger.info("开始代码混淆...")
            
            # 1. 混淆字符串
            obfuscated_code = self.obfuscate_strings(code)
            
            # 2. 混淆函数名
            obfuscated_code = self.obfuscate_function_names(obfuscated_code)
            
            # 3. 添加控制流混淆
            obfuscated_code = self.add_control_flow_obfuscation(obfuscated_code)
            
            # 4. 添加解密函数（如果需要）
            if include_decryption and self.string_obfuscator.obfuscation_counter > 0:
                decryption_function = self.string_obfuscator.generate_decryption_function()
                obfuscated_code = decryption_function + '\n\n' + obfuscated_code
            
            self.logger.info("代码混淆完成")
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"代码混淆失败: {e}")
            return code


class AlgorithmProtector(LoggerMixin):
    """算法保护器"""
    
    def __init__(self):
        self.protected_algorithms = set()
        
    def protect_algorithm(self, algorithm_func: Callable) -> Callable:
        """保护算法函数"""
        def protected_wrapper(*args, **kwargs):
            # 添加反调试检测
            if self._detect_debugging():
                raise RuntimeError("检测到调试环境")
            
            # 执行原始算法
            return algorithm_func(*args, **kwargs)
        
        # 保存保护信息
        self.protected_algorithms.add(algorithm_func.__name__)
        return protected_wrapper
    
    def _detect_debugging(self) -> bool:
        """检测调试环境"""
        import sys
        
        # 检查是否有调试器附加
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            return True
        
        # 检查调试相关的环境变量
        import os
        debug_vars = ['PYCHARM_HOSTED', 'PYTEST_CURRENT_TEST', '_PYDEV_BUNDLE']
        for var in debug_vars:
            if var in os.environ:
                return True
        
        return False
    
    def create_protected_hash_function(self) -> Callable:
        """创建受保护的哈希函数"""
        @self.protect_algorithm
        def protected_hash(data: bytes) -> str:
            """受保护的哈希计算函数"""
            # 使用多重哈希增加破解难度
            sha256 = hashlib.sha256(data).digest()
            md5 = hashlib.md5(sha256).digest()
            final_hash = hashlib.sha1(md5 + sha256).hexdigest()
            
            return final_hash
        
        return protected_hash


class SecurityObfuscator(LoggerMixin):
    """安全混淆器主类"""
    
    def __init__(self, protection_level: str = "medium"):
        self.code_obfuscator = CodeObfuscator()
        self.algorithm_protector = AlgorithmProtector()
        self.protection_level = protection_level
        
        # 保护级别配置
        self.protection_config = {
            "low": {
                "obfuscate_strings": True,
                "obfuscate_functions": False,
                "control_flow": False,
                "algorithm_protection": False
            },
            "medium": {
                "obfuscate_strings": True,
                "obfuscate_functions": True,
                "control_flow": True,
                "algorithm_protection": False
            },
            "high": {
                "obfuscate_strings": True,
                "obfuscate_functions": True,
                "control_flow": True,
                "algorithm_protection": True
            }
        }
    
    def protect_file(self, file_path: str, output_path: str) -> bool:
        """保护Python文件"""
        try:
            # 读取源文件
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # 根据保护级别应用混淆
            config = self.protection_config.get(self.protection_level, self.protection_config["medium"])
            
            protected_code = source_code
            
            if config["obfuscate_strings"] or config["obfuscate_functions"] or config["control_flow"]:
                protected_code = self.code_obfuscator.obfuscate_code(protected_code)
            
            # 添加保护头部注释
            header = self._generate_protection_header()
            protected_code = header + '\n\n' + protected_code
            
            # 写入保护后的文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(protected_code)
            
            self.logger.info(f"文件保护完成: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"文件保护失败: {e}")
            return False
    
    def _generate_protection_header(self) -> str:
        """生成保护头部"""
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
受保护的代码文件
保护级别: {self.protection_level.upper()}
生成时间: {self._get_timestamp()}
警告: 此文件已被混淆保护，请勿尝试逆向工程
"""

import random
import hashlib
from typing import Any'''
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """获取保护统计信息"""
        return {
            'protection_level': self.protection_level,
            'strings_obfuscated': self.string_obfuscator.obfuscation_counter,
            'functions_obfuscated': len(self.code_obfuscator.function_map),
            'identifiers_obfuscated': len(self.code_obfuscator.identifier_map),
            'algorithms_protected': len(self.algorithm_protector.protected_algorithms)
        }


# 示例使用的装饰器
def obfuscated(protection_level: str = "medium"):
    """混淆装饰器"""
    def decorator(func):
        # 这里可以实现运行时的保护逻辑
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


# 受保护的常量
class ProtectedConstants:
    """受保护的常量类"""
    
    def __init__(self):
        self._constants = {}
        self._key = secrets.token_hex(32)
    
    def _simple_encrypt(self, value: str) -> str:
        """简单加密"""
        key_bytes = self._key.encode('utf-8')
        value_bytes = value.encode('utf-8')
        
        encrypted = bytearray()
        for i, byte in enumerate(value_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(encrypted).decode('utf-8')
    
    def _simple_decrypt(self, encrypted_value: str) -> str:
        """简单解密"""
        encrypted_bytes = base64.b64decode(encrypted_value.encode('utf-8'))
        key_bytes = self._key.encode('utf-8')
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted.append(byte ^ key_byte)
        
        return decrypted.decode('utf-8')
    
    def set_constant(self, name: str, value: Any) -> None:
        """设置受保护的常量"""
        encrypted_value = self._simple_encrypt(str(value))
        self._constants[name] = encrypted_value
    
    def get_constant(self, name: str) -> Any:
        """获取受保护的常量"""
        if name not in self._constants:
            raise KeyError(f"常量 {name} 不存在")
        
        encrypted_value = self._constants[name]
        decrypted_value = self._simple_decrypt(encrypted_value)
        
        # 尝试恢复原始类型
        try:
            return eval(decrypted_value)
        except:
            return decrypted_value


if __name__ == "__main__":
    # 测试代码混淆功能
    obfuscator = SecurityObfuscator("high")
    
    test_code = '''
def scan_for_virus(file_path):
    """扫描文件中的病毒"""
    signature = "malware_signature"
    if detect_threat(file_path, signature):
        quarantine_file(file_path)
        return True
    return False

def detect_threat(path, sig):
    return "virus" in path or "trojan" in sig
'''
    
    protected_code = obfuscator.code_obfuscator.obfuscate_code(test_code)
    print("混淆后的代码:")
    print(protected_code)
    
    print("\n保护统计:")
    print(obfuscator.get_protection_stats())