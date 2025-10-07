#!/bin/bash

# OurVerse 一键重启脚本
# 功能：停止所有相关服务，然后重新启动

set -e  # 遇到错误立即退出

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"

echo "🚀 OurVerse 服务重启脚本"
echo "================================="

# 函数：停止服务
stop_services() {
    echo "🛑 停止现有服务..."

    # 停止nginx
    echo "  - 停止nginx..."
    sudo systemctl stop nginx 2>/dev/null || true
    sudo pkill -f nginx 2>/dev/null || true

    # 停止MongoDB Docker容器
    echo "  - 停止MongoDB Docker容器..."
    docker stop ourverse-mongodb 2>/dev/null || true

    # 停止Node.js服务器
    echo "  - 停止Node.js服务器..."
    pkill -f "node server.js" 2>/dev/null || true

    # 等待进程完全停止
    sleep 3

    # 验证端口是否释放
    if lsof -i :8444 >/dev/null 2>&1; then
        echo "❌ 端口8444仍被占用，强制清理..."
        fuser -k 8444/tcp 2>/dev/null || true
        sleep 2
    fi

    if lsof -i :27017 >/dev/null 2>&1; then
        echo "❌ 端口27017仍被占用，强制清理..."
        fuser -k 27017/tcp 2>/dev/null || true
        sleep 2
    fi

    if lsof -i :80 >/dev/null 2>&1 || lsof -i :443 >/dev/null 2>&1; then
        echo "❌ 端口80/443仍被占用，强制清理..."
        fuser -k 80/tcp 443/tcp 2>/dev/null || true
        sleep 2
    fi

    echo "✅ 服务停止完成"
}

# 函数：启动服务
start_services() {
    echo "🚀 启动服务..."

    # 检查MongoDB Docker容器是否在运行
    if docker ps | grep -q ourverse-mongodb; then
        echo "✅ MongoDB Docker容器正在运行"
    else
        echo "❌ MongoDB Docker容器未运行，尝试启动..."
        if docker ps -a | grep -q ourverse-mongodb; then
            echo "  - 启动现有容器..."
            docker start ourverse-mongodb
            sleep 3
        else
            echo "  - 创建并启动MongoDB容器..."
            docker run -d --name ourverse-mongodb -p 27017:27017 -e MONGO_INITDB_ROOT_USERNAME=ourverse -e MONGO_INITDB_ROOT_PASSWORD=ourverse mongo:6.0
            sleep 5
        fi

        if docker ps | grep -q ourverse-mongodb; then
            echo "✅ MongoDB Docker容器启动成功"
        else
            echo "❌ MongoDB Docker容器启动失败"
            echo "  请手动运行: docker start ourverse-mongodb"
            exit 1
        fi
    fi

    # 启动Node.js服务器
    echo "  - 启动Node.js服务器..."
    cd "$BACKEND_DIR"
    nohup npm start > server.log 2>&1 &
    sleep 5

    # 验证Node.js服务器是否启动成功
    if lsof -i :8444 >/dev/null 2>&1; then
        echo "✅ Node.js服务器启动成功 (端口8444)"
    else
        echo "❌ Node.js服务器启动失败，检查日志..."
        tail -20 server.log
        exit 1
    fi

    # 启动nginx
    echo "  - 启动nginx..."
    sudo systemctl start nginx
    sleep 2

    if pgrep -x nginx >/dev/null; then
        echo "✅ nginx启动成功"
    else
        echo "❌ nginx启动失败"
        exit 1
    fi

    echo "✅ 所有服务启动完成"
}

# 函数：检查服务状态
check_services() {
    echo "🔍 检查服务状态..."

    # 检查MongoDB Docker容器
    if docker ps | grep -q ourverse-mongodb; then
        echo "✅ MongoDB: Docker容器运行中"
    else
        echo "❌ MongoDB: Docker容器未运行"
    fi

    # 检查Node.js服务器
    if lsof -i :8444 >/dev/null 2>&1; then
        echo "✅ Node.js服务器: 运行中 (端口8444)"
    else
        echo "❌ Node.js服务器: 未运行"
    fi

    # 检查nginx
    if pgrep -x nginx >/dev/null; then
        echo "✅ nginx: 运行中"
    else
        echo "❌ nginx: 未运行"
    fi
}

# 函数：显示帮助
show_help() {
    echo "OurVerse 服务管理脚本"
    echo ""
    echo "用法:"
    echo "  $0                # 重启所有服务"
    echo "  $0 stop           # 仅停止服务"
    echo "  $0 start          # 仅启动服务"
    echo "  $0 status         # 检查服务状态"
    echo "  $0 logs           # 查看服务器日志"
    echo "  $0 help           # 显示此帮助信息"
    echo ""
    echo "服务包括:"
    echo "  - MongoDB (数据库)"
    echo "  - Node.js服务器 (端口8444)"
    echo "  - nginx (Web服务器)"
}

# 主逻辑
case "${1:-restart}" in
    "stop")
        stop_services
        ;;
    "start")
        start_services
        check_services
        ;;
    "status")
        check_services
        ;;
    "logs")
        echo "📄 服务器日志 (最后20行):"
        echo "---------------------------------"
        if [ -f "$BACKEND_DIR/server.log" ]; then
            tail -20 "$BACKEND_DIR/server.log"
        else
            echo "日志文件不存在"
        fi
        ;;
    "restart")
        stop_services
        echo ""
        start_services
        echo ""
        check_services
        echo ""
        echo "🎉 OurVerse服务重启完成！"
        echo "   网站地址: https://www.our-verse.com"
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo "❌ 未知命令: $1"
        echo ""
        show_help
        exit 1
        ;;
esac