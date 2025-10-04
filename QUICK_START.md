# ⚡ OurVerse Vercel 快速开始

## 🚀 5分钟部署指南

### 步骤 1: 环境准备
```bash
# 1. 复制环境变量模板
cp .vercel.env.example .vercel.env

# 2. 编辑环境变量（替换为你的实际值）
nano .vercel.env
```

### 步骤 2: 配置服务
1. **MongoDB Atlas**: https://mongodb.com/atlas (免费)
2. **GitHub OAuth**: https://github.com/settings/developers
3. **Amap API**: https://lbs.amap.com/ (可选)

### 步骤 3: 一键部署
```bash
# 运行自动部署脚本
./deploy-vercel.sh
```

### 步骤 4: DNS配置
在 NameSilo 中添加 CNAME 记录：
```
Type: CNAME
Host: @
Value: cname.vercel-dns.com
TTL: 3600
```

---

## 📋 必需的环境变量

编辑 `.vercel.env` 文件，填入以下信息：

```bash
# 数据库 (MongoDB Atlas)
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/ourverse

# 认证 (GitHub OAuth)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# 域名
DOMAIN=your-domain.com

# 安全密钥
JWT_SECRET=your-super-secret-key
SESSION_SECRET=your-session-secret

# 地图API (可选)
AMAP_WEB_API_KEY=your_amap_web_key
AMAP_REST_API_KEY=your_amap_rest_key
```

---

## 🧪 测试部署

部署完成后测试：

1. **健康检查**: `https://your-domain.com/health`
2. **应用访问**: `https://your-domain.com/website.html`
3. **GitHub登录**: 检查OAuth是否正常
4. **照片上传**: 测试GPS定位和上传功能

---

## 🆘 常见问题

| 问题 | 解决方法 |
|------|----------|
| MongoDB连接失败 | 检查Atlas IP白名单和连接字符串 |
| GitHub OAuth失败 | 验证回调URL和Client凭据 |
| 地图不显示 | 检查Amap API Key和域名配置 |
| DNS未生效 | 等待5-30分钟，或检查NameSilo配置 |

---

## 📚 详细文档

📖 **完整部署指南**: `VERCEL_DEPLOYMENT.md`

🎯 **项目已准备好，可以直接部署！**
