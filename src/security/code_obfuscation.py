#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码混淆模块 - 关键算法保护、字符串加密、控制流混淆
"""

import os
import ast
import base64
import hashlib
import random
import string
import zlib
from typing import Dict, List, Any, Optional
from pathlib import Path
import importlib.util

from ..utils.logger import LoggerMixin


class StringObfuscator(LoggerMixin):
    """字符串混淆器"""
    
    def __init__(self, key: Optional[str] = None):
        self.key = key or self._generate_key()
        self.obfuscated_strings: Dict[str, str] = {}
        
    def _generate_key(self) -> str:
        """生成混淆密钥"""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    
    def _encrypt_string(self, text: str) -> str:
        """加密字符串"""
        try:
            # 简单的XOR加密
            key_bytes = self.key.encode('utf-8')
            text_bytes = text.encode('utf-8')
            
            encrypted = bytearray()
            for i, byte in enumerate(text_bytes):
                encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
            
            # Base64编码
            encoded = base64.b64encode(encrypted).decode('utf-8')
            return encoded
            
        except Exception as e:
            self.logger.error(f"字符串加密失败: {e}")
            return text
    
    def _decrypt_string(self, encrypted_text: str) -> str:
        """解密字符串"""
        try:
            # Base64解码
            decoded = base64.b64decode(encrypted_text.encode('utf-8'))
            
            # XOR解密
            key_bytes = self.key.encode('utf-8')
            decrypted = bytearray()
            for i, byte in enumerate(decoded):
                decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"字符串解密失败: {e}")
            return encrypted_text
    
    def obfuscate_string(self, text: str) -> str:
        """混淆字符串"""
        if not text or len(text) < 3:  # 跳过太短的字符串
            return text
        
        # 检查是否已经混淆过
        if text in self.obfuscated_strings:
            return self.obfuscated_strings[text]
        
        # 加密并存储
        encrypted = self._encrypt_string(text)
        var_name = f"_s{len(self.obfuscated_strings)}"
        self.obfuscated_strings[text] = var_name
        
        return var_name
    
    def generate_decrypt_code(self) -> str:
        """生成解密代码"""
        decrypt_func = f'''
def _decrypt(encrypted_text):
    import base64
    key = "{self.key}"
    try:
        decoded = base64.b64decode(encrypted_text.encode('utf-8'))
        key_bytes = key.encode('utf-8')
        decrypted = bytearray()
        for i, byte in enumerate(decoded):
            decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return decrypted.decode('utf-8')
    except:
        return encrypted_text

# 混淆的字符串映射
_strings = {{'''
        
        # 添加所有混淆的字符串
        for original, var_name in self.obfuscated_strings.items():
            encrypted = self._encrypt_string(original)
            decrypt_func += f'\n    "{var_name}": _decrypt("{encrypted}"),'
        
        decrypt_func += '\n}\n'
        
        # 添加获取字符串的函数
        decrypt_func += '''
def _gs(key):
    return _strings.get(key, key)
'''
        
        return decrypt_func


class ControlFlowObfuscator(LoggerMixin):
    """控制流混淆器"""
    
    def __init__(self):
        self.dummy_functions: List[str] = []
        self.obfuscation_map: Dict[str, str] = {}
    
    def _generate_dummy_function(self) -> str:
        """生成虚假函数"""
        func_name = f"_f{random.randint(1000, 9999)}"
        operations = [
            "x = random.randint(1, 100)",
            "y = x * 2 + 1", 
            "z = y // 3",
            "result = z % 7",
            "time.sleep(0.001)",
            "len(str(result))"
        ]
        
        selected_ops = random.sample(operations, random.randint(2, 4))
        
        dummy_func = f"""
def {func_name}():
    import random, time
    {'; '.join(selected_ops)}
    return True
"""
        self.dummy_functions.append(dummy_func)
        return func_name
    
    def add_dummy_calls(self, code: str, intensity: int = 3) -> str:
        """添加虚假函数调用"""
        lines = code.split('\n')
        modified_lines = []
        
        for line in lines:
            modified_lines.append(line)
            
            # 在某些行后添加虚假调用
            if random.random() < 0.1 and intensity > 0:  # 10%概率
                dummy_func = self._generate_dummy_function()
                indent = len(line) - len(line.lstrip())
                dummy_call = ' ' * indent + f"if {dummy_func}(): pass"
                modified_lines.append(dummy_call)
        
        return '\n'.join(modified_lines)
    
    def obfuscate_conditions(self, code: str) -> str:
        """混淆条件语句"""
        # 简单的条件混淆：if True and condition -> if condition
        transformations = [
            ('if True and ', 'if '),
            ('if False or ', 'if '),
            ('and True', ''),
            ('or False', ''),
        ]
        
        for old, new in transformations:
            code = code.replace(old, new)
        
        return code


class NameObfuscator(LoggerMixin):
    """名称混淆器"""
    
    def __init__(self):
        self.name_map: Dict[str, str] = {}
        self.reserved_names = {
            'self', 'cls', 'super', 'len', 'str', 'int', 'float', 'list', 'dict',
            'True', 'False', 'None', 'print', 'input', 'range', 'enumerate',
            '__init__', '__str__', '__repr__', 'main', 'run'
        }
    
    def _generate_obfuscated_name(self, original: str) -> str:
        """生成混淆名称"""
        if original in self.name_map:
            return self.name_map[original]
        
        # 生成随机名称
        chars = string.ascii_letters
        length = random.randint(8, 12)
        obfuscated = ''.join(random.choice(chars) for _ in range(length))
        
        # 确保不冲突
        while obfuscated in self.name_map.values():
            obfuscated = ''.join(random.choice(chars) for _ in range(length))
        
        self.name_map[original] = obfuscated
        return obfuscated
    
    def obfuscate_name(self, name: str) -> str:
        """混淆名称"""
        if name in self.reserved_names or name.startswith('_'):
            return name
        
        return self._generate_obfuscated_name(name)


class CodeObfuscator(LoggerMixin):
    """代码混淆器主类"""
    
    def __init__(self):
        self.string_obfuscator = StringObfuscator()
        self.control_flow_obfuscator = ControlFlowObfuscator()
        self.name_obfuscator = NameObfuscator()
        self.protected_files: List[str] = []
    
    def obfuscate_file(self, file_path: str, output_path: Optional[str] = None) -> bool:
        """混淆单个文件"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.logger.error(f"文件不存在: {file_path}")
                return False
            
            # 读取原始代码
            with open(file_path, 'r', encoding='utf-8') as f:
                original_code = f.read()
            
            # 执行混淆
            obfuscated_code = self._obfuscate_code(original_code)
            
            # 确定输出路径
            if output_path is None:
                output_path = file_path.parent / f"{file_path.stem}_obfuscated{file_path.suffix}"
            else:
                output_path = Path(output_path)
            
            # 写入混淆后的代码
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(obfuscated_code)
            
            self.protected_files.append(str(output_path))
            self.logger.info(f"文件混淆完成: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"文件混淆失败: {e}")
            return False
    
    def _obfuscate_code(self, code: str) -> str:
        """混淆代码"""
        try:
            # 1. 解析AST
            tree = ast.parse(code)
            
            # 2. 字符串混淆
            obfuscated_code = self._obfuscate_strings_in_code(code)
            
            # 3. 控制流混淆
            obfuscated_code = self.control_flow_obfuscator.add_dummy_calls(obfuscated_code)
            obfuscated_code = self.control_flow_obfuscator.obfuscate_conditions(obfuscated_code)
            
            # 4. 添加解密代码
            decrypt_code = self.string_obfuscator.generate_decrypt_code()
            obfuscated_code = decrypt_code + '\n\n' + obfuscated_code
            
            # 5. 添加虚假函数
            dummy_functions = '\n'.join(self.control_flow_obfuscator.dummy_functions)
            if dummy_functions:
                obfuscated_code = dummy_functions + '\n\n' + obfuscated_code
            
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"代码混淆失败: {e}")
            return code
    
    def _obfuscate_strings_in_code(self, code: str) -> str:
        """在代码中混淆字符串"""
        lines = code.split('\n')
        modified_lines = []
        
        for line in lines:
            modified_line = line
            
            # 查找字符串字面量（简单实现）
            in_string = False
            quote_char = None
            current_string = ""
            result_line = ""
            i = 0
            
            while i < len(line):
                char = line[i]
                
                if not in_string and char in ['"', "'"]:
                    # 开始字符串
                    in_string = True
                    quote_char = char
                    current_string = ""
                    result_line += char
                elif in_string and char == quote_char:
                    # 结束字符串
                    if current_string and len(current_string) > 2:
                        # 混淆字符串
                        obfuscated_var = self.string_obfuscator.obfuscate_string(current_string)
                        result_line = result_line[:-len(current_string)] + f"_gs('{obfuscated_var}')"
                    else:
                        result_line += current_string + char
                    
                    in_string = False
                    quote_char = None
                    current_string = ""
                elif in_string:
                    current_string += char
                    result_line += char
                else:
                    result_line += char
                
                i += 1
            
            modified_lines.append(result_line)
        
        return '\n'.join(modified_lines)
    
    def obfuscate_directory(self, dir_path: str, output_dir: Optional[str] = None, 
                          file_patterns: List[str] = None) -> bool:
        """混淆目录中的文件"""
        try:
            dir_path = Path(dir_path)
            if not dir_path.exists():
                self.logger.error(f"目录不存在: {dir_path}")
                return False
            
            if output_dir is None:
                output_dir = dir_path.parent / f"{dir_path.name}_obfuscated"
            else:
                output_dir = Path(output_dir)
            
            output_dir.mkdir(exist_ok=True)
            
            # 默认处理Python文件
            if file_patterns is None:
                file_patterns = ['*.py']
            
            success_count = 0
            total_count = 0
            
            for pattern in file_patterns:
                for file_path in dir_path.rglob(pattern):
                    if file_path.is_file():
                        total_count += 1
                        
                        # 保持目录结构
                        relative_path = file_path.relative_to(dir_path)
                        output_file = output_dir / relative_path
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        if self.obfuscate_file(str(file_path), str(output_file)):
                            success_count += 1
            
            self.logger.info(f"目录混淆完成: {success_count}/{total_count} 文件成功处理")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"目录混淆失败: {e}")
            return False
    
    def protect_critical_modules(self, modules: List[str]) -> bool:
        """保护关键模块"""
        try:
            success_count = 0
            
            for module_name in modules:
                # 查找模块文件
                try:
                    spec = importlib.util.find_spec(module_name)
                    if spec and spec.origin:
                        module_path = Path(spec.origin)
                        if module_path.exists():
                            backup_path = module_path.with_suffix('.py.backup')
                            
                            # 备份原文件
                            import shutil
                            shutil.copy2(module_path, backup_path)
                            
                            # 混淆模块
                            if self.obfuscate_file(str(module_path), str(module_path)):
                                success_count += 1
                                self.logger.info(f"关键模块已保护: {module_name}")
                            else:
                                # 恢复备份
                                shutil.copy2(backup_path, module_path)
                                backup_path.unlink()
                
                except ImportError:
                    self.logger.warning(f"无法找到模块: {module_name}")
                    continue
            
            self.logger.info(f"关键模块保护完成: {success_count}/{len(modules)} 个模块")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"关键模块保护失败: {e}")
            return False
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """获取保护统计信息"""
        return {
            'protected_files': len(self.protected_files),
            'obfuscated_strings': len(self.string_obfuscator.obfuscated_strings),
            'dummy_functions': len(self.control_flow_obfuscator.dummy_functions),
            'name_mappings': len(self.name_obfuscator.name_map),
            'files': self.protected_files
        }


class LicenseProtection(LoggerMixin):
    """许可证保护"""
    
    def __init__(self):
        self.license_key = self._generate_license_key()
        self.protection_enabled = True
    
    def _generate_license_key(self) -> str:
        """生成许可证密钥"""
        import uuid
        machine_id = str(uuid.getnode())
        timestamp = str(int(time.time()))
        data = f"{machine_id}-{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def validate_license(self) -> bool:
        """验证许可证"""
        if not self.protection_enabled:
            return True
        
        try:
            # 简单的许可证验证逻辑
            # 在实际实现中，这里应该包含更复杂的验证
            return len(self.license_key) == 64
            
        except Exception as e:
            self.logger.error(f"许可证验证失败: {e}")
            return False
    
    def inject_license_check(self, code: str) -> str:
        """注入许可证检查代码"""
        license_check = f'''
# License Protection
import hashlib, sys, time, uuid
def _check_license():
    try:
        key = "{self.license_key}"
        if len(key) != 64:
            sys.exit(1)
        return True
    except:
        sys.exit(1)

if not _check_license():
    sys.exit(1)

'''
        return license_check + code


# 使用示例和工厂函数
def create_obfuscator() -> CodeObfuscator:
    """创建代码混淆器实例"""
    return CodeObfuscator()


def protect_source_code(source_dir: str, output_dir: str = None, 
                       critical_modules: List[str] = None) -> bool:
    """保护源代码"""
    obfuscator = create_obfuscator()
    
    # 混淆目录
    success = obfuscator.obfuscate_directory(source_dir, output_dir)
    
    # 保护关键模块
    if critical_modules:
        obfuscator.protect_critical_modules(critical_modules)
    
    return success


if __name__ == "__main__":
    # 测试代码混淆
    obfuscator = create_obfuscator()
    
    test_code = '''
def hello_world():
    message = "Hello, World!"
    secret = "This is a secret"
    if True:
        print(message)
        print(secret)
    return "Done"
'''
    
    print("原始代码:")
    print(test_code)
    print("\n" + "="*50 + "\n")
    
    obfuscated = obfuscator._obfuscate_code(test_code)
    print("混淆后代码:")
    print(obfuscated)