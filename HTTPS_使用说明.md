# HTTPS 服务器使用说明

## 问题背景
现代浏览器（特别是iOS Safari和Chrome）要求HTTPS环境才能访问地理位置API。如果通过 `file://` 协议直接打开HTML文件，会被拒绝访问位置信息。

## 解决方案
我们已经创建了一个HTTPS服务器来解决这个问题。

## 使用方法

### 1. 启动HTTPS服务器
```bash
python3 https_server.py
```

### 2. 访问网站
在浏览器中访问：
- 主应用：`https://localhost:8443/website.html`
- 定位测试：`https://localhost:8443/test_location.html`

### 3. 处理安全警告
由于使用自签名证书，浏览器会显示安全警告：
- **Chrome**: 点击"高级" -> "继续访问localhost（不安全）"
- **Safari**: 点击"显示详细信息" -> "访问此网站"
- **Firefox**: 点击"高级" -> "接受风险并继续"

### 4. 测试定位功能
- 页面加载后会自动请求位置权限
- 如果自动定位失败，可以点击"测试定位"按钮使用模拟位置
- 点击"手动定位"按钮重新获取位置

## 文件说明
- `https_server.py`: HTTPS服务器脚本
- `cert.pem`: SSL证书文件
- `key.pem`: SSL私钥文件
- `website.html`: 主网页文件

## 注意事项
1. 首次访问时需要在浏览器中信任自签名证书
2. 确保防火墙允许8443端口访问
3. 在iOS设备上测试时，确保Safari设置中允许了位置访问

## 停止服务器
按 `Ctrl+C` 停止HTTPS服务器 