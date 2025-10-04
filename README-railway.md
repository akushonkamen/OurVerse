# 🚂 OurVerse Railway 部署指南

本指南将帮助您将 OurVerse 照片分享应用部署到 Railway 平台。

## 📋 前置要求

- GitHub 账号
- Railway 账号
- 高德地图 API 密钥

## 🚀 快速部署

### 步骤 1: 连接仓库
1. 登录 Railway 控制台
2. 点击 "New Project"
3. 选择 "Deploy from GitHub repo"
4. 搜索并选择您的 `OurVerse` 仓库
5. 点击 "Deploy"

Railway 会自动检测 `docker-compose.yml` 文件并开始构建。

### 步骤 2: 配置环境变量

在 Railway 控制台中，进入项目设置，为以下变量设置值：

#### 必需变量
```bash
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SESSION_SECRET=your-session-secret-key
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
AMAP_WEB_API_KEY=your_amap_web_api_key
AMAP_REST_API_KEY=your_amap_rest_api_key
AMAP_SECURITY_CODE=your_amap_security_code
```

#### Railway 自动提供的变量（无需手动设置）
- `MONGODB_URI` - 数据库连接字符串
- `PORT` - 应用端口
- `NODE_ENV` - 环境（自动设为 production）

### 步骤 3: 设置自定义域名（可选）

在 Railway 控制台的 "Domains" 部分：
1. 点击 "Add Domain"
2. 输入您的域名
3. 配置 DNS 记录（Railway 会提供所需记录）

## 🔧 项目结构说明

```
/
├── docker-compose.yml    # Railway 容器编排配置
├── Dockerfile           # 应用容器构建配置
├── railway.toml         # Railway 项目配置
├── .dockerignore        # Docker 构建忽略文件
├── server.js            # 主应用文件
├── website.html         # 前端页面
├── package.json         # 依赖配置
├── env.example          # 环境变量示例
├── mongo-init/          # MongoDB 初始化脚本
├── uploads/             # 文件上传目录（持久化存储）
└── logs/                # 日志目录
```

## 📊 服务说明

### MongoDB 服务
- 自动创建 `ourverse` 数据库
- 使用 Railway 提供的持久化存储
- 自动执行初始化脚本创建索引

### 应用服务
- 使用 Node.js 18 Alpine 镜像
- 自动安装生产依赖
- 使用非 root 用户运行
- 内置健康检查

## 🔍 监控和日志

### 查看日志
在 Railway 控制台中：
1. 选择您的服务
2. 点击 "Logs" 标签
3. 查看实时日志输出

### 健康检查
- 自动健康检查路径：`/health`
- 检查频率：每 30 秒
- 超时时间：10 秒

## 🛠️ 故障排除

### 常见问题

1. **构建失败**
   - 检查 `.dockerignore` 文件是否正确
   - 确认所有必需文件都在仓库中

2. **数据库连接失败**
   - 确认 Railway 已成功创建数据库服务
   - 检查环境变量是否正确设置

3. **端口冲突**
   - Railway 自动处理端口分配，无需担心

4. **内存不足**
   - 在 Railway 控制台升级服务计划

### 获取帮助

如果遇到问题：
1. 查看 Railway 控制台的构建日志
2. 检查应用日志输出
3. 参考 [Railway 文档](https://docs.railway.app/)

## 🔒 安全注意事项

1. **环境变量保护**
   - 不要将敏感信息提交到 Git 仓库
   - 使用 Railway 的加密环境变量功能

2. **API 密钥管理**
   - 在 Railway 控制台中设置 API 密钥
   - 不要在代码中硬编码密钥

3. **HTTPS 强制**
   - Railway 自动提供 HTTPS，无需额外配置

## 📈 扩展和维护

### 水平扩展
- 在 Railway 控制台中升级服务规格
- 添加更多实例以处理更高负载

### 备份策略
- Railway 自动备份数据库
- 文件存储在持久化卷中

### 更新部署
- 推送代码到 GitHub 仓库
- Railway 自动检测并重新部署

## 💰 成本估算

### Railway 免费额度
- $5/月免费额度
- 包括 512MB RAM + 1GB 存储

### 起步计划
- $5/月：1GB RAM + 基本存储
- $20/月：2GB RAM + 更高存储

## 🎯 下一步

部署完成后，您可以：

1. **测试应用功能**
   - 访问 Railway 提供的域名
   - 测试用户注册和登录
   - 上传和浏览照片

2. **配置生产环境**
   - 设置 GitHub OAuth 回调 URL
   - 配置高德地图 API
   - 添加监控和警报

3. **性能优化**
   - 根据使用情况调整资源
   - 优化数据库查询
   - 添加缓存策略

---

🎉 恭喜！您的 OurVerse 应用现在运行在 Railway 上！
