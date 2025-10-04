# OurVerse - 照片分享应用

一个基于位置的照片分享应用，支持地理位置标记和附近照片发现功能。

## 📋 文档导航

- ⚡ **[快速开始](QUICK_START.md)** - 5分钟部署指南
- 📖 **[详细部署](VERCEL_DEPLOYMENT.md)** - 完整Vercel部署教程
- 🐳 **Docker部署** - 传统自托管方式
- 📚 **API文档** - 开发者接口说明

## 🚀 快速开始

### 部署选项

选择适合你的部署方式：

#### ⚡ Vercel 部署（推荐，5分钟完成）
```bash
# 1. 复制环境变量模板
cp .vercel.env.example .vercel.env

# 2. 编辑环境变量（填入你的配置）
nano .vercel.env

# 3. 一键部署
./deploy-vercel.sh
```

**优势**: 自动HTTPS、全球CDN、零运维成本

**适合**: 新手用户、快速原型、小型应用

#### 🐳 Docker 部署（传统方式）
```bash
# 自动部署
./deploy.sh

# 手动启动
docker-compose up -d
```

**适合**: 完全控制、自托管服务器

### 前置要求

#### Vercel 部署
- NameSilo 域名
- Vercel 账户
- MongoDB Atlas 账户（免费）
- GitHub OAuth 应用

#### Docker 部署
- Node.js 16+
- MongoDB 6.0+
- Docker & Docker Compose
- GitHub OAuth 应用

### 环境配置

#### Vercel 环境配置
```bash
# 复制 Vercel 环境变量模板
cp .vercel.env.example .vercel.env

# 编辑环境变量
nano .vercel.env
```

**必需的环境变量**:
```bash
# 数据库 (MongoDB Atlas - 免费)
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/ourverse

# 认证 (GitHub OAuth)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# 域名 (你的 NameSilo 域名)
DOMAIN=your-domain.com

# 安全密钥
JWT_SECRET=your-super-secret-jwt-key
SESSION_SECRET=your-session-secret-key

# 可选: 高德地图 API
AMAP_WEB_API_KEY=your_amap_web_key
AMAP_REST_API_KEY=your_amap_rest_key
```

#### Docker 环境配置
```bash
cp env.example .env
```

#### 开发环境配置
编辑 `.env` 文件，开发环境使用以下配置：

```bash
# 数据库连接
MONGODB_URI=mongodb://localhost:27017/ourverse

# JWT 密钥（生产环境请使用强密码）
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# 服务器配置
PORT=8444
NODE_ENV=development
DOMAIN=localhost
PROTOCOL=http
FRONTEND_URL=http://localhost:8444
```

#### 生产环境配置
生产环境使用HTTPS协议：

```bash
# 服务器配置
NODE_ENV=production
DOMAIN=your-domain.com
PROTOCOL=https
FRONTEND_URL=https://your-domain.com
GITHUB_CALLBACK_URL=https://your-domain.com/api/auth/github/callback
```

#### GitHub OAuth 配置
1. 在 GitHub 上创建 OAuth 应用
2. 设置授权回调 URL：`https://your-domain.com/api/auth/github/callback`
3. 填写以下配置：
```bash
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=https://your-domain.com/api/auth/github/callback
```

#### 高德地图 API 配置
从 [高德地图开放平台](https://lbs.amap.com/) 获取密钥：
```bash
AMAP_WEB_API_KEY=your_web_api_key_here
AMAP_REST_API_KEY=your_rest_api_key_here
AMAP_SECURITY_CODE=your_security_code_here
```

### 安装和运行

#### 本地开发
```bash
# 安装依赖
npm install

# 启动服务
npm run dev

# 访问应用
open http://localhost:8444/website.html
```

#### Docker 部署
```bash
# 自动部署
./deploy.sh

# 或者手动启动
docker-compose up -d

# 访问应用
open http://localhost
```

## 📋 环境变量配置详解

### 数据库配置
- `MONGODB_URI`: MongoDB 连接字符串

### 认证和安全
- `JWT_SECRET`: JWT 令牌签名密钥
- `BCRYPT_SALT_ROUNDS`: 密码哈希盐轮数（默认: 10）

### OAuth 配置
- `GITHUB_CLIENT_ID`: GitHub OAuth 客户端 ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth 客户端密钥
- `GITHUB_CALLBACK_URL`: GitHub OAuth 回调 URL

### 域名和协议配置
- `DOMAIN`: 应用域名
- `PROTOCOL`: 协议（http/https）
- `FRONTEND_URL`: 前端访问地址

### 服务器配置
- `PORT`: 服务器端口（默认: 8444）
- `NODE_ENV`: 环境模式（development/production）
- `API_BASE_URL`: API 基础 URL

### 高德地图 API 配置
- `AMAP_WEB_API_KEY`: Web 端 JS API 密钥
- `AMAP_REST_API_KEY`: Web 服务 API 密钥
- `AMAP_SECURITY_CODE`: 安全密钥

### 文件上传配置
- `MAX_FILE_SIZE`: 最大文件大小（字节，默认: 10MB）
- `ALLOWED_FILE_TYPES`: 允许的文件类型（逗号分隔）
- `UPLOADS_DIR`: 上传文件目录（默认: uploads）

### 业务逻辑参数
- `DAILY_UPLOAD_LIMIT`: 每日上传限制（默认: 3张）
- `MAX_DISTANCE_VERIFICATION`: 距离验证最大值（米，默认: 50米）
- `LOCATION_VERIFICATION_RADIUS`: 位置验证半径

### 速率限制
- `RATE_LIMIT_WINDOW_MS`: 速率限制窗口（毫秒，默认: 15分钟）
- `RATE_LIMIT_MAX_REQUESTS`: 最大请求数（默认: 100）

### 会话配置
- `SESSION_COOKIE_MAX_AGE`: 会话 Cookie 最大年龄（毫秒）
- `SESSION_SECRET`: 会话密钥

### Docker 配置
- `DOCKER_APP_PORT`: 应用容器端口（默认: 3000）
- `DOCKER_NGINX_HTTP_PORT`: Nginx HTTP 端口（默认: 80）
- `DOCKER_NGINX_HTTPS_PORT`: Nginx HTTPS 端口（默认: 443）

### 其他配置
- `HEALTH_CHECK_PORT`: 健康检查端口（默认: 3000）
- `CORS_ORIGIN`: CORS 允许源
- `LOG_LEVEL`: 日志级别（默认: info）

## 🔧 部署指南

### Vercel 部署（推荐）

#### 自动部署
```bash
# 一键部署脚本
./deploy-vercel.sh
```

#### 手动部署
```bash
# 1. 安装 Vercel CLI
npm install -g vercel

# 2. 登录 Vercel
vercel login

# 3. 部署到生产环境
vercel --prod

# 4. 添加自定义域名
vercel domains add your-domain.com
```

#### DNS 配置
在 NameSilo 中添加 CNAME 记录：
```
Type: CNAME
Host: @
Value: cname.vercel-dns.com
TTL: 3600
```

#### 优势特点
- ✅ **自动 HTTPS**: 免费 SSL 证书
- ✅ **全球 CDN**: 快速访问体验
- ✅ **自动扩展**: 根据流量自动调整
- ✅ **零运维**: Vercel 处理所有基础设施
- ✅ **免费额度**: 每月 100GB 流量

### Docker 部署（传统方式）

#### 生产环境部署

1. **域名和 SSL 证书**
   ```bash
   # 更新域名配置
   DOMAIN=your-domain.com
   PROTOCOL=https

   # 配置 SSL 证书路径
   SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
   SSL_KEY_PATH=/etc/nginx/ssl/key.pem
   ```

2. **更新 API 密钥**
   ```bash
   # 使用生产环境的真实密钥
   AMAP_WEB_API_KEY=your_production_web_key
   AMAP_REST_API_KEY=your_production_rest_key
   ```

3. **生成安全的密钥**
   ```bash
   # 生成 JWT 密钥
   openssl rand -hex 32

   # 生成会话密钥
   openssl rand -hex 32
   ```

4. **启动生产环境**
   ```bash
   NODE_ENV=production docker-compose up -d
   ```

### 故障排除

#### 常见问题

1. **OAuth 回调失败**
   - 检查 `GITHUB_CALLBACK_URL` 是否与 GitHub 应用配置一致
   - 确保域名解析正确

2. **地图功能异常**
   - 验证高德地图 API 密钥是否有效
   - 检查网络连接和防火墙设置

3. **文件上传失败**
   - 检查 `MAX_FILE_SIZE` 设置
   - 确认 `UPLOADS_DIR` 目录存在且可写

4. **数据库连接失败**
   - 验证 `MONGODB_URI` 格式正确
   - 检查 MongoDB 服务状态

#### 日志查看
```bash
# 查看应用日志
docker-compose logs app

# 查看 Nginx 日志
docker-compose logs nginx

# 查看 MongoDB 日志
docker-compose logs mongodb
```

## 🔒 安全建议

1. **生产环境密钥**
   - 使用强密码作为 JWT 和会话密钥
   - 定期更换 API 密钥

2. **HTTPS 配置**
   - 生产环境必须启用 HTTPS
   - 配置正确的 SSL 证书

3. **防火墙设置**
   - 限制不必要的端口暴露
   - 配置合适的速率限制

4. **数据备份**
   - 定期备份 MongoDB 数据
   - 备份上传的文件

## 📚 API 文档

### 认证端点
- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户登录
- `GET /api/auth/verify` - 验证令牌
- `GET /api/auth/github` - GitHub OAuth 登录
- `GET /api/auth/github/callback` - GitHub OAuth 回调

### 照片管理
- `POST /api/photos/upload` - 上传照片
- `GET /api/photos/nearby` - 获取附近照片
- `GET /api/photos/my` - 获取我的照片
- `GET /api/photos/:id` - 获取照片详情
- `POST /api/photos/:id/comments` - 添加评论

### 位置服务
- `GET /api/amap/config` - 获取地图配置
- `GET /api/location/ip` - IP 定位
- `GET /api/location/regeo` - 逆地理编码

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 项目
2. 创建功能分支：`git checkout -b feature/amazing-feature`
3. 提交更改：`git commit -m 'Add amazing feature'`
4. 推送分支：`git push origin feature/amazing-feature`
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Express.js](https://expressjs.com/) - Web 框架
- [MongoDB](https://www.mongodb.com/) - 数据库
- [高德地图](https://lbs.amap.com/) - 地图服务
- [Passport.js](http://www.passportjs.org/) - 认证中间件
