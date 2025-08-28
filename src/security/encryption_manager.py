#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据加密存储和通信安全机制
提供数据加密、安全存储和通信保护功能
"""

import os
import json
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ssl
import hmac

from ..utils.logger import LoggerMixin


class EncryptionManager(LoggerMixin):
    """加密管理器"""
    
    def __init__(self, key_storage_path: str = "/tmp/android_security_keys"):
        self.key_storage_path = key_storage_path
        self.master_key = None
        self.symmetric_cipher = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self._ensure_key_storage()
        self._initialize_encryption()
    
    def _ensure_key_storage(self):
        """确保密钥存储目录存在"""
        try:
            os.makedirs(self.key_storage_path, exist_ok=True, mode=0o700)
        except Exception as e:
            self.logger.error(f"创建密钥存储目录失败: {e}")
    
    def _initialize_encryption(self):
        """初始化加密组件"""
        try:
            # 生成或加载主密钥
            master_key_file = os.path.join(self.key_storage_path, "master.key")
            
            if os.path.exists(master_key_file):
                with open(master_key_file, 'rb') as f:
                    self.master_key = f.read()
            else:
                self.master_key = Fernet.generate_key()
                with open(master_key_file, 'wb') as f:
                    f.write(self.master_key)
                os.chmod(master_key_file, 0o600)
            
            self.symmetric_cipher = Fernet(self.master_key)
            
            # 生成或加载RSA密钥对
            self._initialize_rsa_keys()
            
        except Exception as e:
            self.logger.error(f"加密组件初始化失败: {e}")
    
    def _initialize_rsa_keys(self):
        """初始化RSA密钥对"""
        try:
            private_key_file = os.path.join(self.key_storage_path, "rsa_private.pem")
            public_key_file = os.path.join(self.key_storage_path, "rsa_public.pem")
            
            if os.path.exists(private_key_file) and os.path.exists(public_key_file):
                # 加载现有密钥
                with open(private_key_file, 'rb') as f:
                    self.rsa_private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                
                with open(public_key_file, 'rb') as f:
                    self.rsa_public_key = serialization.load_pem_public_key(f.read())
            else:
                # 生成新密钥对
                self.rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048
                )
                self.rsa_public_key = self.rsa_private_key.public_key()
                
                # 保存密钥
                with open(private_key_file, 'wb') as f:
                    f.write(self.rsa_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                os.chmod(private_key_file, 0o600)
                
                with open(public_key_file, 'wb') as f:
                    f.write(self.rsa_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                
        except Exception as e:
            self.logger.error(f"RSA密钥初始化失败: {e}")
    
    def encrypt_data(self, data: str) -> str:
        """对称加密数据"""
        try:
            encrypted = self.symmetric_cipher.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            self.logger.error(f"数据加密失败: {e}")
            return ""
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """对称解密数据"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.symmetric_cipher.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            self.logger.error(f"数据解密失败: {e}")
            return ""
    
    def encrypt_with_rsa(self, data: str) -> str:
        """RSA加密数据"""
        try:
            encrypted = self.rsa_public_key.encrypt(
                data.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            self.logger.error(f"RSA加密失败: {e}")
            return ""
    
    def decrypt_with_rsa(self, encrypted_data: str) -> str:
        """RSA解密数据"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.rsa_private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            self.logger.error(f"RSA解密失败: {e}")
            return ""


class SecureDataStore(LoggerMixin):
    """安全数据存储"""
    
    def __init__(self, encryption_manager: EncryptionManager, 
                 storage_path: str = "/tmp/android_security_data"):
        self.encryption_manager = encryption_manager
        self.storage_path = storage_path
        self._ensure_storage_directory()
    
    def _ensure_storage_directory(self):
        """确保存储目录存在"""
        try:
            os.makedirs(self.storage_path, exist_ok=True, mode=0o700)
        except Exception as e:
            self.logger.error(f"创建存储目录失败: {e}")
    
    def store_secure_data(self, key: str, data: Dict[str, Any], 
                         encrypt_sensitive: bool = True) -> bool:
        """安全存储数据"""
        try:
            # 添加元数据
            storage_data = {
                'data': data,
                'timestamp': datetime.now().isoformat(),
                'checksum': self._calculate_checksum(data),
                'encrypted': encrypt_sensitive
            }
            
            # 序列化数据
            json_data = json.dumps(storage_data, ensure_ascii=False, indent=2)
            
            # 加密敏感数据
            if encrypt_sensitive:
                json_data = self.encryption_manager.encrypt_data(json_data)
            
            # 写入文件
            file_path = os.path.join(self.storage_path, f"{key}.enc")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(json_data)
            
            os.chmod(file_path, 0o600)
            
            self.logger.info(f"数据安全存储成功: {key}")
            return True
            
        except Exception as e:
            self.logger.error(f"安全存储失败: {e}")
            return False
    
    def load_secure_data(self, key: str) -> Optional[Dict[str, Any]]:
        """加载安全数据"""
        try:
            file_path = os.path.join(self.storage_path, f"{key}.enc")
            
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 解密数据（如果已加密）
            try:
                # 尝试解密
                decrypted_content = self.encryption_manager.decrypt_data(content)
                if decrypted_content:
                    content = decrypted_content
            except:
                # 如果解密失败，假设数据未加密
                pass
            
            # 解析JSON
            storage_data = json.loads(content)
            
            # 验证校验和
            if not self._verify_checksum(storage_data['data'], storage_data.get('checksum')):
                self.logger.warning(f"数据校验和验证失败: {key}")
            
            return storage_data['data']
            
        except Exception as e:
            self.logger.error(f"加载安全数据失败: {e}")
            return None
    
    def delete_secure_data(self, key: str) -> bool:
        """删除安全数据"""
        try:
            file_path = os.path.join(self.storage_path, f"{key}.enc")
            
            if os.path.exists(file_path):
                # 安全删除：先覆写再删除
                with open(file_path, 'wb') as f:
                    f.write(os.urandom(os.path.getsize(file_path)))
                
                os.remove(file_path)
                self.logger.info(f"安全数据已删除: {key}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"删除安全数据失败: {e}")
            return False
    
    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """计算数据校验和"""
        try:
            json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
            return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
        except Exception as e:
            self.logger.error(f"计算校验和失败: {e}")
            return ""
    
    def _verify_checksum(self, data: Dict[str, Any], expected_checksum: str) -> bool:
        """验证校验和"""
        if not expected_checksum:
            return True
        
        calculated_checksum = self._calculate_checksum(data)
        return calculated_checksum == expected_checksum


class SecureCommunication(LoggerMixin):
    """安全通信"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self.api_keys: Dict[str, str] = {}
        self.session_tokens: Dict[str, Dict[str, Any]] = {}
    
    def generate_api_key(self, client_id: str) -> str:
        """生成API密钥"""
        try:
            api_key = secrets.token_urlsafe(32)
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            
            self.api_keys[client_id] = key_hash
            
            self.logger.info(f"API密钥已生成: {client_id}")
            return api_key
            
        except Exception as e:
            self.logger.error(f"生成API密钥失败: {e}")
            return ""
    
    def verify_api_key(self, client_id: str, api_key: str) -> bool:
        """验证API密钥"""
        try:
            if client_id not in self.api_keys:
                return False
            
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            return hmac.compare_digest(self.api_keys[client_id], key_hash)
            
        except Exception as e:
            self.logger.error(f"验证API密钥失败: {e}")
            return False
    
    def create_session_token(self, client_id: str, expiry_minutes: int = 60) -> str:
        """创建会话令牌"""
        try:
            token = secrets.token_urlsafe(24)
            
            session_data = {
                'client_id': client_id,
                'created_time': datetime.now(),
                'expiry_minutes': expiry_minutes,
                'permissions': ['read', 'write']  # 可配置权限
            }
            
            self.session_tokens[token] = session_data
            
            self.logger.info(f"会话令牌已创建: {client_id}")
            return token
            
        except Exception as e:
            self.logger.error(f"创建会话令牌失败: {e}")
            return ""
    
    def verify_session_token(self, token: str) -> Optional[Dict[str, Any]]:
        """验证会话令牌"""
        try:
            if token not in self.session_tokens:
                return None
            
            session_data = self.session_tokens[token]
            
            # 检查是否过期
            created_time = session_data['created_time']
            expiry_minutes = session_data['expiry_minutes']
            
            if (datetime.now() - created_time).total_seconds() > expiry_minutes * 60:
                del self.session_tokens[token]
                return None
            
            return session_data
            
        except Exception as e:
            self.logger.error(f"验证会话令牌失败: {e}")
            return None
    
    def encrypt_communication_data(self, data: Dict[str, Any], recipient_public_key: str = None) -> str:
        """加密通信数据"""
        try:
            json_data = json.dumps(data, ensure_ascii=False)
            
            if recipient_public_key:
                # 使用接收者的公钥加密
                return self.encryption_manager.encrypt_with_rsa(json_data)
            else:
                # 使用对称加密
                return self.encryption_manager.encrypt_data(json_data)
                
        except Exception as e:
            self.logger.error(f"通信数据加密失败: {e}")
            return ""
    
    def decrypt_communication_data(self, encrypted_data: str, use_rsa: bool = False) -> Optional[Dict[str, Any]]:
        """解密通信数据"""
        try:
            if use_rsa:
                json_data = self.encryption_manager.decrypt_with_rsa(encrypted_data)
            else:
                json_data = self.encryption_manager.decrypt_data(encrypted_data)
            
            if json_data:
                return json.loads(json_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"通信数据解密失败: {e}")
            return None
    
    def create_secure_ssl_context(self) -> ssl.SSLContext:
        """创建安全SSL上下文"""
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # 安全配置
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            return context
            
        except Exception as e:
            self.logger.error(f"创建SSL上下文失败: {e}")
            return ssl.create_default_context()


class SecurityManager(LoggerMixin):
    """安全管理器"""
    
    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.secure_store = SecureDataStore(self.encryption_manager)
        self.secure_comm = SecureCommunication(self.encryption_manager)
        self.audit_log: List[Dict[str, Any]] = []
        
    def initialize_security(self) -> bool:
        """初始化安全组件"""
        try:
            # 检查加密组件
            if not self.encryption_manager.symmetric_cipher:
                return False
            
            # 测试加密解密
            test_data = "security_test_data"
            encrypted = self.encryption_manager.encrypt_data(test_data)
            decrypted = self.encryption_manager.decrypt_data(encrypted)
            
            if decrypted != test_data:
                return False
            
            self.log_security_event("SECURITY_INIT", "安全组件初始化成功", "SUCCESS")
            return True
            
        except Exception as e:
            self.logger.error(f"安全初始化失败: {e}")
            self.log_security_event("SECURITY_INIT", f"安全组件初始化失败: {e}", "ERROR")
            return False
    
    def log_security_event(self, event_type: str, description: str, status: str, client_id: str = "system"):
        """记录安全事件"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'description': description,
            'status': status,
            'client_id': client_id,
            'event_id': secrets.token_hex(8)
        }
        
        self.audit_log.append(event)
        
        # 限制日志大小
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-500:]
        
        self.logger.info(f"安全事件记录: {event_type} - {description}")
    
    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态"""
        try:
            return {
                'encryption_enabled': bool(self.encryption_manager.symmetric_cipher),
                'rsa_keys_available': bool(self.encryption_manager.rsa_private_key),
                'secure_storage_ready': os.path.exists(self.secure_store.storage_path),
                'active_sessions': len(self.secure_comm.session_tokens),
                'audit_events_count': len(self.audit_log),
                'last_security_check': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"获取安全状态失败: {e}")
            return {'error': str(e)}
    
    def cleanup_expired_sessions(self):
        """清理过期会话"""
        try:
            current_time = datetime.now()
            expired_tokens = []
            
            for token, session_data in self.secure_comm.session_tokens.items():
                created_time = session_data['created_time']
                expiry_minutes = session_data['expiry_minutes']
                
                if (current_time - created_time).total_seconds() > expiry_minutes * 60:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                del self.secure_comm.session_tokens[token]
            
            if expired_tokens:
                self.log_security_event("SESSION_CLEANUP", f"清理了{len(expired_tokens)}个过期会话", "SUCCESS")
            
        except Exception as e:
            self.logger.error(f"清理过期会话失败: {e}")
            self.log_security_event("SESSION_CLEANUP", f"清理过期会话失败: {e}", "ERROR")
