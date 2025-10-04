#!/bin/bash

# OurVerse Vercel 部署脚本
echo "🚀 开始部署 OurVerse 到 Vercel..."

# 检查是否安装了 Vercel CLI
if ! command -v vercel &> /dev/null; then
    echo "❌ 未安装 Vercel CLI，请先运行: npm install -g vercel"
    exit 1
fi

# 检查是否已登录
if ! vercel whoami &> /dev/null; then
    echo "🔐 请先登录 Vercel:"
    vercel login
fi

# 检查环境变量文件
if [ ! -f ".env.vercel" ]; then
    echo "⚠️  未找到 .env.vercel 文件"
    echo "请创建 .env.vercel 文件并配置以下变量："
    echo ""
    echo "# 数据库配置"
    echo "MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/ourverse"
    echo ""
    echo "# 认证配置"
    echo "JWT_SECRET=your-jwt-secret"
    echo "BCRYPT_SALT_ROUNDS=10"
    echo ""
    echo "# GitHub OAuth"
    echo "GITHUB_CLIENT_ID=your_github_client_id"
    echo "GITHUB_CLIENT_SECRET=your_github_client_secret"
    echo ""
    echo "# 域名配置"
    echo "DOMAIN=your-domain.com"
    echo ""
    echo "# 高德地图"
    echo "AMAP_WEB_API_KEY=your_amap_web_key"
    echo "AMAP_REST_API_KEY=your_amap_rest_key"
    echo ""
    read -p "按回车键创建模板文件..."
    cat > .env.vercel << 'EOF'
# ==========================================
# OurVerse Vercel 环境变量配置
# ==========================================

# 数据库配置
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/ourverse?retryWrites=true&w=majority

# 认证配置
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
BCRYPT_SALT_ROUNDS=10

# GitHub OAuth 配置
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here

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
EOF
    echo "✅ 已创建 .env.vercel 模板文件"
    echo "请编辑文件并填入正确的配置值，然后重新运行此脚本"
    exit 1
fi

# 部署到 Vercel
echo "📦 部署到 Vercel..."
vercel --prod

# 检查部署状态
if [ $? -eq 0 ]; then
    echo "✅ 部署成功！"
    echo ""
    echo "🔗 访问您的应用：https://your-domain.com"
    echo ""
    echo "📋 下一步操作："
    echo "1. 在 Vercel 控制台配置环境变量（或使用 vercel env add）"
    echo "2. 配置自定义域名"
    echo "3. 测试应用功能"
    echo ""
    echo "📖 详细文档请查看 VERCEL_DEPLOYMENT.md"
else
    echo "❌ 部署失败，请检查错误信息"
    exit 1
fi