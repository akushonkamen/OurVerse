# HTTPS 服务器使用说明

## 问题背景
现代浏览器（特别是iOS Safari和Chrome）要求HTTPS环境才能访问地理位置API。如果通过 `file://` 协议直接打开HTML文件，会被拒绝访问位置信息。

## 解决方案
我们已经创建了一个HTTPS服务器来解决这个问题，支持自动生成SSL证书和端口冲突处理。

## 使用方法

### 方法一：使用启动脚本（推荐）
```bash
./start_server.sh
```

### 方法二：直接运行Python脚本
```bash
python3 https_server.py
```

### 3. 访问网站
服务器启动后，在浏览器中访问：
- 主应用：`https://localhost:8443/website.html`
- 目录浏览：`https://localhost:8443/`

### 4. 处理安全警告
由于使用自签名证书，浏览器会显示安全警告：
- **Chrome**: 点击"高级" -> "继续访问localhost（不安全）"
- **Safari**: 点击"显示详细信息" -> "访问此网站"
- **Firefox**: 点击"高级" -> "接受风险并继续"

### 5. 测试定位功能
- 页面加载后会自动请求位置权限
- 如果自动定位失败，可以点击"测试定位"按钮使用模拟位置
- 点击"手动定位"按钮重新获取位置

## 新功能特性

### 🔧 自动SSL证书生成
- 首次运行时会自动生成自签名SSL证书
- 证书有效期为365天
- 无需手动配置证书文件

### 🔄 智能端口管理
- 自动检测端口占用情况
- 如果默认端口8443被占用，会自动选择其他可用端口
- 支持端口范围8443-8542

### 🛡️ 错误处理
- 完善的错误提示和处理机制
- 环境检查（Python、OpenSSL）
- 优雅的服务器停止处理

## 文件说明
- `https_server.py`: HTTPS服务器脚本（改进版）
- `start_server.sh`: 便捷启动脚本
- `cert.pem`: SSL证书文件（自动生成）
- `key.pem`: SSL私钥文件（自动生成）
- `website.html`: 主网页文件

## 系统要求
- Python 3.6+
- OpenSSL（macOS: `brew install openssl`）
- 支持的操作系统：macOS、Linux、Windows

## 注意事项
1. 首次运行时会自动生成SSL证书，可能需要几秒钟
2. 确保防火墙允许服务器端口访问
3. 在iOS设备上测试时，确保Safari设置中允许了位置访问
4. 如果遇到端口冲突，服务器会自动选择其他端口

## 停止服务器
按 `Ctrl+C` 停止HTTPS服务器

## 故障排除

### 端口被占用
如果看到"Address already in use"错误：
```bash
# 查看占用端口的进程
lsof -i :8443

# 终止进程
kill <PID>
```

### SSL证书问题
如果SSL证书生成失败：
```bash
# 删除现有证书文件
rm cert.pem key.pem

# 重新运行服务器
python3 https_server.py
```

### 权限问题
如果启动脚本无法执行：
```bash
chmod +x start_server.sh
``` 