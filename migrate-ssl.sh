#!/bin/bash

# SSL证书迁移脚本
# 功能：从A服务器迁移SSL证书到B服务器，或使用certbot重新申请
# 用法：
#   迁移证书: ./migrate-ssl.sh migrate <source_server> [source_user] [source_key]
#   重新申请: ./migrate-ssl.sh renew

set -e

DOMAIN="our-verse.com"
NGINX_CONF="/etc/nginx/sites-available/ourverse"
LETSENCRYPT_DIR="/etc/letsencrypt"
CERT_PATH="$LETSENCRYPT_DIR/live/$DOMAIN"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 函数：检查证书文件是否存在
check_cert_files() {
    if [ -f "$CERT_PATH/fullchain.pem" ] && [ -f "$CERT_PATH/privkey.pem" ]; then
        return 0
    fi
    return 1
}

# 函数：验证证书有效性
verify_cert() {
    if [ -f "$CERT_PATH/fullchain.pem" ]; then
        local expiry=$(sudo openssl x509 -enddate -noout -in "$CERT_PATH/fullchain.pem" 2>/dev/null | cut -d= -f2)
        if [ -n "$expiry" ]; then
            log_info "证书有效期至: $expiry"
            return 0
        fi
    fi
    return 1
}

# 函数：从A服务器迁移证书
migrate_cert() {
    local source_server="$1"
    local source_user="${2:-ubuntu}"
    local source_key="${3:-}"
    
    log_info "开始从A服务器迁移SSL证书..."
    log_info "源服务器: $source_server"
    
    # 构建SSH命令
    local ssh_cmd="ssh"
    if [ -n "$source_key" ]; then
        ssh_cmd="$ssh_cmd -i $source_key"
    fi
    ssh_cmd="$ssh_cmd $source_user@$source_server"
    
    # 检查A服务器上的证书
    log_info "检查A服务器上的证书..."
    if ! $ssh_cmd "test -f $CERT_PATH/fullchain.pem && test -f $CERT_PATH/privkey.pem"; then
        log_error "A服务器上未找到证书文件"
        exit 1
    fi
    
    # 检查A服务器上的整个letsencrypt目录
    log_info "检查A服务器上的Let's Encrypt目录..."
    if ! $ssh_cmd "test -d $LETSENCRYPT_DIR"; then
        log_error "A服务器上未找到Let's Encrypt目录"
        exit 1
    fi
    
    # 创建本地目录
    log_info "创建本地证书目录..."
    sudo mkdir -p "$LETSENCRYPT_DIR"
    sudo mkdir -p "$CERT_PATH"
    
    # 迁移证书文件
    log_info "迁移证书文件..."
    if [ -n "$source_key" ]; then
        sudo rsync -avz -e "ssh -i $source_key" \
            "$source_user@$source_server:$CERT_PATH/" "$CERT_PATH/"
        
        # 迁移整个letsencrypt目录（包括账户信息和续期配置）
        log_info "迁移Let's Encrypt配置..."
        sudo rsync -avz -e "ssh -i $source_key" \
            --exclude='archive' \
            --exclude='keys' \
            "$source_user@$source_server:$LETSENCRYPT_DIR/" "$LETSENCRYPT_DIR/"
    else
        sudo rsync -avz \
            "$source_user@$source_server:$CERT_PATH/" "$CERT_PATH/"
        
        sudo rsync -avz \
            --exclude='archive' \
            --exclude='keys' \
            "$source_user@$source_server:$LETSENCRYPT_DIR/" "$LETSENCRYPT_DIR/"
    fi
    
    # 设置正确的权限
    log_info "设置证书文件权限..."
    sudo chmod 755 "$LETSENCRYPT_DIR"
    sudo chmod 755 "$LETSENCRYPT_DIR/live"
    sudo chmod 755 "$CERT_PATH"
    sudo chmod 644 "$CERT_PATH/fullchain.pem" 2>/dev/null || true
    sudo chmod 600 "$CERT_PATH/privkey.pem" 2>/dev/null || true
    
    # 验证证书
    if verify_cert; then
        log_info "证书迁移成功"
        return 0
    else
        log_error "证书验证失败"
        return 1
    fi
}

# 函数：修复nginx配置为HTTP模式
fix_nginx_http() {
    log_info "修复nginx配置为HTTP模式（certbot需要nginx先运行）..."
    
    # 备份当前配置
    if [ -f "$NGINX_CONF" ]; then
        sudo cp "$NGINX_CONF" "${NGINX_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # 创建HTTP配置（不使用SSL）
    sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    client_max_body_size 0;

    # CORS Header 配置
    add_header Access-Control-Allow-Origin http://www.$DOMAIN;
    add_header Access-Control-Allow-Credentials true;
    add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE';
    add_header Access-Control-Allow-Headers 'Content-Type, Authorization, X-Requested-With, X-Access-Token';

    location / {
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        
        # 确保请求头正确转发
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Cookie \$http_cookie;
        proxy_cache_bypass \$http_upgrade;
        
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
    if [ ! -L "/etc/nginx/sites-enabled/ourverse" ]; then
        sudo ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/ourverse"
    fi
    
    # 测试并启动nginx
    log_info "测试nginx配置..."
    if sudo nginx -t; then
        log_info "nginx配置测试通过，启动nginx..."
        sudo systemctl restart nginx
        sleep 2
        
        if sudo systemctl is-active --quiet nginx; then
            log_info "nginx启动成功（HTTP模式）"
            return 0
        else
            log_error "nginx启动失败"
            return 1
        fi
    else
        log_error "nginx配置测试失败"
        return 1
    fi
}

# 函数：使用certbot重新申请证书
renew_cert() {
    log_info "使用certbot重新申请SSL证书..."
    
    # 检查certbot是否安装
    if ! command -v certbot &> /dev/null; then
        log_info "安装certbot..."
        sudo apt-get update
        sudo apt-get install -y certbot python3-certbot-nginx
    fi
    
    # 先修复nginx配置为HTTP模式（certbot需要nginx先运行）
    if ! fix_nginx_http; then
        log_error "无法修复nginx配置，无法继续申请证书"
        return 1
    fi
    
    # 使用certbot申请证书并自动配置nginx
    log_info "申请SSL证书（需要域名解析指向本服务器）..."
    log_info "certbot将自动配置nginx启用HTTPS..."
    
    if sudo certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email admin@$DOMAIN 2>&1 | tee /tmp/certbot.log; then
        log_info "证书申请成功"
        
        # 验证nginx配置
        if sudo nginx -t; then
            sudo systemctl reload nginx
            log_info "nginx已重新加载SSL配置"
        fi
        
        return 0
    else
        log_error "证书申请失败，请检查："
        log_error "1. 域名DNS是否指向本服务器"
        log_error "2. 端口80和443是否开放"
        log_error "3. nginx是否正常运行"
        cat /tmp/certbot.log
        return 1
    fi
}

# 函数：配置nginx使用SSL证书
configure_nginx() {
    log_info "配置nginx使用SSL证书..."
    
    if ! check_cert_files; then
        log_error "证书文件不存在，无法配置nginx"
        return 1
    fi
    
    # 备份当前配置
    if [ -f "$NGINX_CONF" ]; then
        sudo cp "$NGINX_CONF" "${NGINX_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # 创建完整的nginx SSL配置
    log_info "更新nginx配置..."
    sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    client_max_body_size 0;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate $CERT_PATH/fullchain.pem;
    ssl_certificate_key $CERT_PATH/privkey.pem;

    # SSL配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    client_max_body_size 0;

    # CORS Header 配置
    add_header Access-Control-Allow-Origin https://www.$DOMAIN;
    add_header Access-Control-Allow-Credentials true;
    add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE';
    add_header Access-Control-Allow-Headers 'Content-Type, Authorization, X-Requested-With, X-Access-Token';

    # SSL 强制 HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        
        # 确保请求头正确转发
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Cookie \$http_cookie;
        proxy_cache_bypass \$http_upgrade;
        
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
    
    # 测试nginx配置
    log_info "测试nginx配置..."
    if sudo nginx -t; then
        log_info "nginx配置测试通过"
        
        # 重启nginx
        log_info "重启nginx..."
        sudo systemctl restart nginx
        sleep 2
        
        if sudo systemctl is-active --quiet nginx; then
            log_info "nginx重启成功"
            return 0
        else
            log_error "nginx重启失败"
            return 1
        fi
    else
        log_error "nginx配置测试失败"
        return 1
    fi
}

# 函数：设置certbot自动续期
setup_auto_renewal() {
    log_info "设置certbot自动续期..."
    
    # 检查续期任务是否已存在
    if sudo crontab -l 2>/dev/null | grep -q "certbot renew"; then
        log_info "自动续期任务已存在"
        return 0
    fi
    
    # 添加续期任务（每天检查，到期前30天续期）
    (sudo crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | sudo crontab -
    log_info "已添加自动续期任务（每天凌晨3点检查）"
}

# 主逻辑
case "${1:-}" in
    "migrate")
        if [ -z "$2" ]; then
            log_error "请指定源服务器地址"
            echo "用法: $0 migrate <source_server> [source_user] [source_key]"
            exit 1
        fi
        
        if migrate_cert "$2" "${3:-ubuntu}" "${4:-}"; then
            if configure_nginx; then
                log_info "SSL证书迁移完成！"
                log_warn "注意：Let's Encrypt证书迁移后，自动续期可能无法正常工作"
                log_warn "建议：使用 'certbot renew --dry-run' 测试续期功能"
                log_warn "或者：使用 '$0 renew' 重新申请证书（推荐）"
            else
                log_error "nginx配置失败"
                exit 1
            fi
        else
            log_error "证书迁移失败"
            exit 1
        fi
        ;;
    "renew")
        if renew_cert; then
            setup_auto_renewal
            log_info "SSL证书申请完成！"
        else
            log_error "证书申请失败"
            exit 1
        fi
        ;;
    "configure")
        if configure_nginx; then
            log_info "nginx SSL配置完成！"
        else
            log_error "配置失败"
            exit 1
        fi
        ;;
    "verify")
        if check_cert_files; then
            log_info "证书文件存在"
            verify_cert
        else
            log_error "证书文件不存在"
            exit 1
        fi
        ;;
    *)
        echo "SSL证书迁移脚本"
        echo ""
        echo "用法:"
        echo "  迁移证书（从A服务器）:"
        echo "    $0 migrate <source_server> [source_user] [source_key]"
        echo ""
        echo "  重新申请证书（推荐）:"
        echo "    $0 renew"
        echo ""
        echo "  仅配置nginx（证书已存在）:"
        echo "    $0 configure"
        echo ""
        echo "  验证证书:"
        echo "    $0 verify"
        echo ""
        echo "示例:"
        echo "  # 从A服务器迁移证书"
        echo "  ./migrate-ssl.sh migrate 192.168.1.100 ubuntu ~/.ssh/id_rsa"
        echo ""
        echo "  # 使用certbot重新申请（推荐）"
        echo "  ./migrate-ssl.sh renew"
        echo ""
        echo "⚠️  注意："
        echo "  - Let's Encrypt证书迁移后，自动续期可能无法正常工作"
        echo "  - 推荐使用certbot重新申请证书，确保续期正常"
        echo "  - 重新申请需要域名DNS指向本服务器"
        exit 1
        ;;
esac

