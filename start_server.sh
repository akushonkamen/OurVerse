#!/bin/bash

# 网站展示 HTTPS 服务器启动脚本

echo "🚀 启动网站展示 HTTPS 服务器..."
echo ""

# 检查 Python 是否安装
if ! command -v python3 &> /dev/null; then
    echo "❌ 错误：未找到 Python3，请先安装 Python"
    exit 1
fi

# 检查 OpenSSL 是否安装
if ! command -v openssl &> /dev/null; then
    echo "❌ 错误：未找到 OpenSSL，请先安装 OpenSSL"
    echo "macOS 安装命令：brew install openssl"
    exit 1
fi

# 启动服务器
echo "✅ 环境检查通过，正在启动服务器..."
echo ""

python3 https_server.py 