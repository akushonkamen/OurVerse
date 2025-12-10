#!/bin/bash

# 修复nginx配置 - 临时禁用SSL，让服务先启动

set -e

NGINX_CONF="/etc/nginx/sites-available/ourverse"
NGINX_ENABLED="/etc/nginx/sites-enabled/ourverse"

echo "🔧 修复nginx配置..."

# 备份原配置
if [ -f "$NGINX_CONF" ]; then
    sudo cp "$NGINX_CONF" "${NGINX_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
    echo "✅ 已备份原配置"
fi

# 创建临时配置（不使用SSL）
sudo tee "$NGINX_CONF" > /dev/null <<'EOF'
server {
    listen 80;
    server_name our-verse.com www.our-verse.com;
    client_max_body_size 0;

    # CORS Header 配置
    add_header Access-Control-Allow-Origin http://www.our-verse.com;
    add_header Access-Control-Allow-Credentials true;
    add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE';
    add_header Access-Control-Allow-Headers 'Content-Type, Authorization, X-Requested-With, X-Access-Token';

    location / {
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        
        # 确保请求头正确转发
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Cookie $http_cookie;
        proxy_cache_bypass $http_upgrade;
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # 静态文件缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        proxy_pass http://127.0.0.1:8444;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # 健康检查
    location /health {
        proxy_pass http://127.0.0.1:8444;
        access_log off;
    }
}
EOF

# 确保符号链接存在
if [ ! -L "$NGINX_ENABLED" ]; then
    sudo ln -s "$NGINX_CONF" "$NGINX_ENABLED"
fi

# 测试配置
echo "🧪 测试nginx配置..."
if sudo nginx -t; then
    echo "✅ nginx配置测试通过"
    echo "🚀 启动nginx..."
    sudo systemctl restart nginx
    sleep 2
    
    if sudo systemctl is-active --quiet nginx; then
        echo "✅ nginx启动成功"
        echo ""
        echo "⚠️  注意：当前使用HTTP（端口80），未启用SSL"
        echo "📝 如需启用HTTPS，请："
        echo "   1. 安装SSL证书（使用certbot）："
        echo "      sudo apt-get install certbot python3-certbot-nginx"
        echo "      sudo certbot --nginx -d our-verse.com -d www.our-verse.com"
        echo ""
        echo "   2. 或者手动配置SSL证书路径后，恢复A服务器的配置"
    else
        echo "❌ nginx启动失败，请检查日志: sudo journalctl -xeu nginx.service"
        exit 1
    fi
else
    echo "❌ nginx配置测试失败"
    exit 1
fi

