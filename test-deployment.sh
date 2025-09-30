#!/bin/bash

echo "🧪 测试OurVerse部署配置..."

# 检查Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker未安装"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose未安装"
    exit 1
fi

echo "✅ Docker环境正常"

# 检查配置文件
configs=(".env" "docker-compose.yml" "Dockerfile" "nginx.conf")
for config in "${configs[@]}"; do
    if [ -f "$config" ]; then
        echo "✅ $config 存在"
    else
        echo "❌ $config 缺失"
        exit 1
    fi
done

# 检查脚本权限
scripts=("deploy.sh" "start-production.sh")
for script in "${scripts[@]}"; do
    if [ -x "$script" ]; then
        echo "✅ $script 可执行"
    else
        echo "⚠️  $script 权限不足，运行: chmod +x $script"
    fi
done

echo ""
echo "🎉 所有配置检查通过！"
echo ""
echo "🚀 现在可以运行以下命令启动应用："
echo "   ./deploy.sh          # 自动部署"
echo "   ./start-production.sh # 生产环境启动"
echo "   docker-compose up -d # 手动启动"
echo ""
echo "📖 详细配置说明请查看：生产环境设置指南.md"
