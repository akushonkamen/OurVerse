# OurVerse Vercel 部署指南

## 概述

本指南将帮助您将 OurVerse 项目部署到 Vercel 上。项目已经过修改以支持 Vercel 的 serverless 环境。

## 前置要求

1. **Vercel 账户**：访问 [vercel.com](https://vercel.com) 注册账户
2. **MongoDB Atlas**：免费的 MongoDB 云数据库
3. **域名**：您已经购买的域名
4. **GitHub 账户**：用于代码部署

## 步骤 1：设置 MongoDB Atlas

1. 访问 [MongoDB Atlas](https://www.mongodb.com/atlas)
2. 创建免费账户并集群
3. 创建数据库用户
4. 获取连接字符串，格式如下：
   ```
   mongodb+srv://username:password@cluster.mongodb.net/ourverse?retryWrites=true&w=majority
   ```

## 步骤 2：配置 Vercel 项目

### 2.1 导入项目到 Vercel

1. 登录 Vercel 控制台
2. 点击 "New Project"
3. 连接您的 GitHub 仓库
4. 选择 OurVerse 项目

### 2.2 配置环境变量

在 Vercel 项目设置中添加以下环境变量：

```
# 数据库配置
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/ourverse?retryWrites=true&w=majority

# 认证配置
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
BCRYPT_SALT_ROUNDS=10

# GitHub OAuth 配置
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=https://your-domain.com/api/auth/github/callback

# 域名配置
DOMAIN=your-domain.com
PROTOCOL=https
FRONTEND_URL=https://your-domain.com

# 高德地图配置
AMAP_WEB_API_KEY=your_amap_web_api_key_here
AMAP_REST_API_KEY=your_amap_rest_api_key_here
AMAP_SECURITY_CODE=your_amap_security_code_here

# 文件上传配置
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=image/jpeg,image/png,image/gif,image/webp

# 业务逻辑参数
DAILY_UPLOAD_LIMIT=3
MAX_DISTANCE_VERIFICATION=50

# 速率限制
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# 会话配置
SESSION_COOKIE_MAX_AGE=86400000
SESSION_SECRET=your-session-secret-key
```

## 步骤 3：配置域名

### 3.1 在 Vercel 中添加自定义域名

1. 在 Vercel 项目中进入 "Settings" → "Domains"
2. 添加您的域名：`your-domain.com`
3. Vercel 会显示所需的 DNS 配置

### 3.2 在 Namesilo 中配置 DNS

1. 登录 Namesilo 控制台
2. 找到您的域名，点击 "Manage DNS"
3. 根据 Vercel 提供的配置添加记录：

   **类型 A 记录：**
   - 主机名：@
   - 类型：A
   - 地址：76.76.21.21

   **类型 CNAME 记录：**
   - 主机名：www
   - 类型：CNAME
   - 目标：cname.vercel-dns.com

## 步骤 4：部署项目

1. 在 Vercel 中点击 "Deploy"
2. 等待部署完成
3. 访问您的域名检查应用是否正常工作

## 步骤 5：配置 GitHub OAuth

### 5.1 创建 GitHub OAuth App

1. 访问 [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. 点击 "New OAuth App"
3. 填写信息：
   - Application name: OurVerse
   - Homepage URL: `https://your-domain.com`
   - Authorization callback URL: `https://your-domain.com/api/auth/github/callback`
4. 获取 Client ID 和 Client Secret

### 5.2 更新 Vercel 环境变量

在 Vercel 中更新：
```
GITHUB_CLIENT_ID=your_actual_client_id
GITHUB_CLIENT_SECRET=your_actual_client_secret
```

## 步骤 6：测试功能

1. **基本功能测试**：
   - 访问网站首页
   - 尝试注册/登录
   - 测试位置定位
   - 上传照片

2. **性能检查**：
   - 图片加载速度
   - API 响应时间
   - 地图功能

## 注意事项

### Vercel 限制

1. **执行时间**：每个请求最多 30 秒
2. **内存**：免费计划限制内存使用
3. **文件存储**：不支持持久化文件存储（已通过 base64 解决）

### 数据库连接

- MongoDB Atlas 免费集群有连接限制
- 考虑升级到付费计划以获得更好性能

### 图片存储

- 当前使用 base64 编码存储在数据库中
- 大量图片可能影响数据库性能
- 考虑使用云存储服务（如 AWS S3、Cloudinary）

## 故障排除

### 常见问题

1. **部署失败**：
   - 检查环境变量配置
   - 确认 MongoDB 连接字符串正确

2. **图片不显示**：
   - 检查 base64 数据是否正确生成
   - 确认浏览器支持 base64 图片

3. **OAuth 登录失败**：
   - 确认 GitHub OAuth 配置正确
   - 检查回调 URL 匹配

4. **地图不工作**：
   - 确认高德地图 API 密钥有效
   - 检查网络连接

### 日志查看

在 Vercel 控制台的 "Functions" 标签页查看 serverless 函数日志。

## 后续优化建议

1. **图片存储**：集成云存储服务
2. **缓存**：添加 Redis 缓存
3. **CDN**：使用 Vercel 的全球 CDN
4. **监控**：设置错误监控和性能监控

## 技术支持

如果遇到问题，请检查：
1. Vercel 部署日志
2. MongoDB Atlas 连接状态
3. 环境变量配置
4. 域名 DNS 配置