#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单验证闪退问题解决方案
"""

import sys
import os

print("=" * 50)
print("闪退问题解决方案验证")
print("=" * 50)

# 检查Python版本
print(f"Python版本: {sys.version}")
version = sys.version_info
if version >= (3, 8):
    print("✅ Python版本检查通过")
else:
    print("❌ Python版本过低")

# 检查关键文件
files_to_check = [
    "main.py",
    "start_safe.py", 
    "config.ini",
    "requirements.txt",
    "快速使用指南.md"
]

print("\n检查关键文件:")
for file_name in files_to_check:
    if os.path.exists(file_name):
        print(f"✅ {file_name}")
    else:
        print(f"❌ {file_name} 缺失")

# 检查关键目录
dirs_to_check = [
    "src",
    "src/utils", 
    "src/gui",
    "logs"
]

print("\n检查关键目录:")
for dir_name in dirs_to_check:
    if os.path.exists(dir_name):
        print(f"✅ {dir_name}")
    else:
        print(f"❌ {dir_name} 缺失")

# 检查关键模块
modules_to_check = [
    "tkinter",
    "pathlib",
    "configparser",
    "logging"
]

print("\n检查内置模块:")
for module_name in modules_to_check:
    try:
        __import__(module_name)
        print(f"✅ {module_name}")
    except ImportError:
        print(f"❌ {module_name} 无法导入")

print("\n" + "=" * 50)
print("验证完成！")
print("\n📋 使用说明:")
print("1. 首次使用请运行: python start_safe.py")
print("2. 查看详细指南: 快速使用指南.md")
print("3. 直接启动: python main.py")
print("=" * 50)