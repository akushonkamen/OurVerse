#!/bin/bash

# OurVerse 生产环境启动脚本

echo "🚀 启动 OurVerse 生产环境..."

# 检查环境文件
if [ ! -f .env ]; then
    echo "❌ 错误：未找到 .env 文件"
    echo "请复制 .env.example 为 .env 并配置环境变量"
    exit 1
fi

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo "❌ 错误：未找到 Docker，请先安装 Docker"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ 错误：未找到 Docker Compose，请先安装 Docker Compose"
    exit 1
fi

# 创建必要目录
echo "📁 创建必要目录..."
mkdir -p uploads logs ssl

# 生成 SSL 证书（如果不存在）
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
    echo "🔐 生成自签名 SSL 证书..."
    mkdir -p ssl
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=OurVerse/CN=localhost"
fi

# 构建和启动服务
echo "🐳 构建和启动 Docker 服务..."
docker-compose up -d --build

# 等待服务启动
echo "⏳ 等待服务启动..."
sleep 10

# 检查服务状态
echo "🔍 检查服务状态..."
if docker-compose ps | grep -q "Up"; then
    echo "✅ 服务启动成功！"
    echo ""
    echo "🌐 访问地址:"
    echo "   HTTP:  http://localhost"
    echo "   HTTPS: https://localhost"
    echo "   API:   http://localhost:3000"
    echo ""
    echo "📱 移动端访问: https://$(hostname -I | awk '{print $1}')"
    echo ""
    echo "🛠️  管理命令:"
    echo "   查看日志: docker-compose logs -f"
    echo "   停止服务: docker-compose down"
    echo "   重启服务: docker-compose restart"
else
    echo "❌ 服务启动失败"
    echo "查看日志: docker-compose logs"
    exit 1
fi
