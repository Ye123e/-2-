# Android系统修复工具

一个基于Python的图形化Android设备系统修复工具，提供全方位的Android设备维护解决方案。

## 🚀 功能特性

- **设备连接管理**: 自动检测和连接Android设备（USB/WiFi）
- **系统诊断**: 全面的系统健康检查
- **病毒扫描**: 检测和清除恶意软件
- **资源修复**: 修复丢失的系统资源和库文件
- **错误文件清理**: 识别和清理损坏、冗余文件
- **一键修复**: 自动化的系统修复流程
- **图形化界面**: 用户友好的操作界面

## 📋 系统要求

- Python 3.8 或更高版本
- Android Debug Bridge (ADB)
- Windows 10/11 或 Linux/macOS

## 🔧 安装说明

### 1. 克隆项目
```bash
git clone <repository-url>
cd android-system-repair-tool
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 安装Android SDK Platform Tools
确保ADB工具已安装并添加到系统PATH中。

**Windows:**
1. 下载 [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
2. 解压到合适目录
3. 将目录路径添加到系统环境变量PATH

**Linux/macOS:**
```bash
# Ubuntu/Debian
sudo apt install android-tools-adb

# macOS (使用Homebrew)
brew install android-platform-tools
```

### 4. 启用开发者选项
在Android设备上：
1. 进入 设置 → 关于手机
2. 连续点击"版本号" 7次启用开发者选项
3. 进入 设置 → 开发者选项
4. 启用"USB调试"

## 🎯 使用方法

### 启动应用
```bash
python main.py
```

### 基本操作流程
1. **连接设备**: 使用USB数据线连接Android设备到电脑
2. **设备授权**: 在设备上确认USB调试授权
3. **刷新设备**: 点击"刷新设备"按钮检测连接的设备
4. **选择设备**: 在设备列表中选择要修复的设备
5. **系统诊断**: 切换到"系统诊断"标签页，选择检查项目并开始诊断
6. **执行修复**: 根据诊断结果，在"修复操作"标签页执行相应的修复操作

## 📁 项目结构

```
android-system-repair-tool/
├── main.py                 # 主程序入口
├── config.ini             # 配置文件
├── requirements.txt        # 依赖包列表
├── README.md              # 项目说明
├── src/                   # 源代码目录
│   ├── __init__.py
│   ├── config/            # 配置管理
│   ├── core/              # 核心功能模块
│   │   ├── device_manager.py    # 设备管理器
│   │   ├── diagnostic_engine.py # 诊断引擎 (开发中)
│   │   ├── repair_engine.py     # 修复引擎 (开发中)
│   │   └── security_scanner.py  # 安全扫描器 (开发中)
│   ├── gui/               # 图形界面
│   │   └── main_window.py       # 主窗口
│   ├── models/            # 数据模型
│   └── utils/             # 工具函数
│       └── logger.py            # 日志记录器
├── data/                  # 数据文件
├── logs/                  # 日志文件
├── backups/              # 备份文件
└── tests/                # 测试文件
```

## 🔍 当前开发状态

### ✅ 已完成功能
- [x] 项目架构搭建
- [x] 设备连接和检测
- [x] ADB通信管理
- [x] 基础GUI界面
- [x] 设备信息显示
- [x] 配置管理系统
- [x] 日志记录系统

### 🚧 开发中功能
- [ ] 系统诊断引擎
- [ ] 病毒检测扫描器
- [ ] 资源修复模块
- [ ] 错误文件清理
- [ ] 修复引擎
- [ ] 网络修复服务

### 📅 计划功能
- [ ] 批量设备管理
- [ ] 远程修复支持
- [ ] AI智能诊断
- [ ] 自定义修复脚本
- [ ] 社区修复方案

## 🛠️ 开发说明

### 技术栈
- **GUI框架**: Tkinter (内置)
- **Android通信**: ADB + adb-shell
- **安全扫描**: yara-python, pyclamd
- **核心依赖**: requests, psutil, pillow

### 运行测试
```bash
# 安装测试依赖
pip install pytest pytest-cov

# 运行测试
pytest tests/

# 生成覆盖率报告
pytest --cov=src tests/
```

### 代码规范
```bash
# 代码格式化
black src/

# 代码检查
flake8 src/

# 类型检查
mypy src/
```

## 🐛 故障排除

### 常见问题

1. **ADB设备检测失败**
   - 确保ADB已正确安装并添加到PATH
   - 检查USB调试是否已启用
   - 尝试重新连接设备

2. **设备连接授权失败**
   - 在设备上确认USB调试授权对话框
   - 检查USB数据线是否支持数据传输
   - 尝试更换USB端口

3. **Python依赖安装失败**
   - 升级pip版本: `pip install --upgrade pip`
   - 使用国内镜像: `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt`

### 日志查看
应用运行日志保存在 `logs/app.log` 文件中，可以通过日志定位问题。

## 📞 支持和贡献

如果您遇到问题或有建议，欢迎：
- 提交Issue报告问题
- 提交Pull Request贡献代码
- 在讨论区分享使用经验

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## ⚠️ 免责声明

本工具仅用于合法的设备维护目的。使用本工具修复设备前，请确保已备份重要数据。作者不对使用本工具造成的任何数据丢失或设备损坏承担责任。