#!/usr/bin/env bash
set -euo pipefail

# 快速在阿里云 ECS 上部署 OurVerse 后端 + MongoDB
# 需以 root 或 sudo 运行，支持 Debian/Ubuntu 与 RHEL/CentOS 系列

if [ "${EUID}" -ne 0 ]; then
    echo "[错误] 请使用 sudo 或 root 账户运行此脚本" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infra/docker-compose.yml"
ENV_FILE="$REPO_ROOT/.env"
SERVICE_FILE="/etc/systemd/system/ourverse.service"
UPLOADS_DIR="$REPO_ROOT/backend/uploads"
LOGS_DIR="$REPO_ROOT/backend/logs"
ORIGINAL_USER="${SUDO_USER:-root}"

log() {
    local level="$1"; shift
    printf '[%s] %s\n' "$level" "$*"
}

require_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        log 错误 "缺少文件: $file"
        exit 1
    fi
}

require_file "$COMPOSE_FILE"

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    else
        log 错误 "无法识别操作系统"
        exit 1
    fi

    case "$OS_ID" in
        ubuntu|debian|linuxmint)
            PKG_MGR="apt"
            ;;
        centos|almalinux|rocky|ol|anolis|rhel)
            PKG_MGR="dnf"
            ;;
        amzn)
            PKG_MGR="dnf"
            ;;
        *)
            log 错误 "暂不支持的系统: $OS_ID $OS_VERSION"
            exit 1
            ;;
    esac
}

install_base_packages() {
    if [ "$PKG_MGR" = "apt" ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y ca-certificates curl gnupg lsb-release git ufw openssl
    else
        dnf -y install ca-certificates curl gnupg2 git firewalld openssl
    fi
}

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log 信息 "Docker 已安装"
        systemctl enable --now docker >/dev/null 2>&1 || true
        return
    fi

    log 信息 "安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
}

install_compose_plugin() {
    if docker compose version >/dev/null 2>&1; then
        log 信息 "docker compose 插件已可用"
        return
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        log 信息 "将使用 docker-compose 二进制"
        return
    fi

    if [ "$PKG_MGR" = "apt" ]; then
        apt-get install -y docker-compose-plugin
    else
        dnf -y install docker-compose-plugin
    fi

    if ! docker compose version >/dev/null 2>&1; then
        log 错误 "docker compose 插件安装失败"
        exit 1
    fi
}

ensure_compose_command() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose -f "$COMPOSE_FILE")
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose -f "$COMPOSE_FILE")
    else
        log 错误 "未检测到 docker compose"
        exit 1
    fi
}

prompt_value() {
    local prompt="$1"; local default="$2"; local allow_empty="${3:-false}"; local value
    while true; do
        read -r -p "$prompt [$default]: " value || value=""
        if [ -z "$value" ]; then
            value="$default"
        fi
        if [ "$allow_empty" = "true" ] || [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
    done
}

prompt_sensitive() {
    local prompt="$1"; local default="$2"; local value
    read -r -s -p "$prompt [$default]: " value || value=""
    printf '\n'
    if [ -z "$value" ]; then
        value="$default"
    fi
    printf '%s' "$value"
}

fetch_default_domain() {
    local ip
    ip=$(curl -fsSL http://100.100.100.200/latest/meta-data/public-ipv4 2>/dev/null || true)
    if [ -z "$ip" ]; then
        ip=$(curl -fsSL https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -n "$ip" ]; then
        printf '%s' "$ip"
    else
        printf '%s' "localhost"
    fi
}

prepare_directories() {
    mkdir -p "$UPLOADS_DIR" "$LOGS_DIR"
    if [ "$ORIGINAL_USER" != "root" ]; then
        chown -R "$ORIGINAL_USER":"$ORIGINAL_USER" "$UPLOADS_DIR" "$LOGS_DIR"
    fi
}

create_env_file() {
    local default_domain default_protocol app_port domain protocol mongo_user mongo_pass_default mongo_pass mongo_db mongo_port jwt_secret session_secret daily_limit max_distance amap_web amap_rest amap_code github_id github_secret github_token allowed_origins frontend_url custom_callback

    default_domain=$(fetch_default_domain)
    default_protocol="https"
    if [ "$default_domain" = "localhost" ]; then
        default_protocol="http"
    fi

    log 信息 "配置环境变量 (.env)"
    app_port=$(prompt_value "应用访问端口" "3000")
    domain=$(prompt_value "公网访问域名或IP" "$default_domain")
    protocol=$(prompt_value "访问协议 (http/https)" "$default_protocol")

    mongo_user=$(prompt_value "MongoDB 管理员用户名" "ourverse")
    mongo_pass_default="$(openssl rand -hex 12)"
    mongo_pass=$(prompt_sensitive "MongoDB 管理员密码" "$mongo_pass_default")
    mongo_db=$(prompt_value "MongoDB 数据库" "ourverse")
    mongo_port=$(prompt_value "MongoDB 暴露端口" "27017")

    jwt_secret="$(openssl rand -hex 32)"
    session_secret="$(openssl rand -hex 32)"

    daily_limit=$(prompt_value "每日上传次数限制" "5")
    max_distance=$(prompt_value "最大距离验证 (km)" "50")

    amap_web=$(prompt_value "高德 Web 服务 key (可留空)" "" true)
    amap_rest=$(prompt_value "高德 REST key (可留空)" "" true)
    amap_code=$(prompt_value "高德安全码 (可留空)" "" true)

    github_id=$(prompt_value "GitHub OAuth Client ID (可留空)" "" true)
    github_secret=$(prompt_sensitive "GitHub OAuth Client Secret (可留空)" "")
    github_token=$(prompt_sensitive "GitHub Personal Access Token (可留空)" "")

    allowed_origins=$(prompt_value "后端允许的跨域来源" "$protocol://$domain")
    frontend_url=$(prompt_value "前端应用地址" "$protocol://$domain")
    custom_callback=$(prompt_value "GitHub OAuth 回调地址" "$protocol://$domain/api/auth/github/callback")

    cat > "$ENV_FILE" <<EOENV
NODE_ENV=production
HOST=0.0.0.0
PORT=$app_port
APP_PORT=$app_port

MONGO_USERNAME=$mongo_user
MONGO_PASSWORD=$mongo_pass
MONGO_PORT=$mongo_port
MONGO_INITDB_DATABASE=$mongo_db
MONGODB_URI=mongodb://$mongo_user:$mongo_pass@mongodb:27017/$mongo_db?authSource=admin

JWT_SECRET=$jwt_secret
SESSION_SECRET=$session_secret

ALLOWED_ORIGINS=$allowed_origins
FRONTEND_URL=$frontend_url
UPLOADS_DIR=uploads
DAILY_UPLOAD_LIMIT=$daily_limit
MAX_DISTANCE_VERIFICATION=$max_distance
BCRYPT_SALT_ROUNDS=10

AMAP_WEB_API_KEY=$amap_web
AMAP_REST_API_KEY=$amap_rest
AMAP_SECURITY_CODE=$amap_code
GITHUB_CLIENT_ID=$github_id
GITHUB_CLIENT_SECRET=$github_secret
GITHUB_CALLBACK_URL=$custom_callback
GITHUB_TOKEN=$github_token
PROTOCOL=$protocol
DOMAIN=$domain
EOENV

    chmod 640 "$ENV_FILE"
    if [ "$ORIGINAL_USER" != "root" ]; then
        chown "$ORIGINAL_USER":"$ORIGINAL_USER" "$ENV_FILE"
    fi

    export APP_PORT="$app_port"
    export MONGO_PORT="$mongo_port"
    export MONGO_USERNAME="$mongo_user"
    export MONGO_PASSWORD="$mongo_pass"
    export MONGO_DATABASE="$mongo_db"
    export DOMAIN="$domain"
    export PROTOCOL="$protocol"
}

bring_up_stack() {
    log 信息 "启动容器服务"
    (${COMPOSE_CMD[@]} pull mongodb >/dev/null 2>&1 || true)
    (${COMPOSE_CMD[@]} build app)
    (${COMPOSE_CMD[@]} up -d)
}

wait_for_health() {
    local retries=20
    local delay=6
    local url="http://127.0.0.1:${APP_PORT}/health"
    log 信息 "等待 API 健康检查 (${url})"
    for ((i=1; i<=retries; i++)); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            log 成功 "API 健康检查通过"
            return
        fi
        sleep "$delay"
    done
    log 错误 "API 健康检查失败，请查看 docker 日志"
    (${COMPOSE_CMD[@]} logs --tail=200 || true)
    exit 1
}

create_systemd_unit() {
    log 信息 "创建 systemd 服务 ($SERVICE_FILE)"
    cat > "$SERVICE_FILE" <<EOSERVICE
[Unit]
Description=OurVerse 容器化栈
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$REPO_ROOT/infra
ExecStart=/usr/bin/env bash -lc 'docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d --build'
ExecStop=/usr/bin/env bash -lc 'docker compose -f "$REPO_ROOT/infra/docker-compose.yml" down'
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOSERVICE

    systemctl daemon-reload
    systemctl enable ourverse.service
    systemctl restart ourverse.service
}

open_firewall_ports() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${APP_PORT}"/tcp >/dev/null 2>&1 || true
        ufw allow "${MONGO_PORT}"/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${APP_PORT}"/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="${MONGO_PORT}"/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

summarise() {
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$host_ip" ]; then
        host_ip="127.0.0.1"
    fi
    cat <<EOSUM
============================================================
🎉 部署完成
- API 访问:        ${PROTOCOL}://${DOMAIN}:${APP_PORT}
- 健康检查:        http://$host_ip:${APP_PORT}/health
- MongoDB 内网:     mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongodb:27017/${MONGO_DATABASE}?authSource=admin (容器内)
- MongoDB 宿主机:   mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@127.0.0.1:${MONGO_PORT}/${MONGO_DATABASE}?authSource=admin
- systemd 服务:     systemctl status ourverse.service
- 更新：           cd $REPO_ROOT && sudo ./infra/aliyun-oneclick.sh
============================================================
EOSUM
}

main() {
    detect_os
    install_base_packages
    install_docker
    install_compose_plugin
    ensure_compose_command
    prepare_directories
    create_env_file
    bring_up_stack
    wait_for_health
    create_systemd_unit
    open_firewall_ports
    summarise
}

main "$@"
