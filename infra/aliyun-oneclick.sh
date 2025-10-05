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
BACKEND_ENV="$REPO_ROOT/backend/.env"

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
require_file "$BACKEND_ENV"

get_env_value_from_file() {
    local file="$1" key="$2"
    grep -E "^${key}=" "$file" | tail -n1 | cut -d= -f2-
}

to_lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

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

prepare_directories() {
    mkdir -p "$UPLOADS_DIR" "$LOGS_DIR"
    if [ "$ORIGINAL_USER" != "root" ]; then
        chown -R "$ORIGINAL_USER":"$ORIGINAL_USER" "$UPLOADS_DIR" "$LOGS_DIR"
    fi
}

set_env_value() {
    local file="$1" key="$2" value="$3"
    local escaped
    escaped=$(printf '%s' "$value" | sed 's/[\\/&]/\\&/g')
    if grep -q "^${key}=" "$file"; then
        sed -i.bak "s|^${key}=.*|${key}=${escaped}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

create_env_file() {
    log 信息 "复制本地 backend/.env 配置"
    cp "$BACKEND_ENV" "$ENV_FILE"

    local app_port
    app_port=$(get_env_value_from_file "$ENV_FILE" "PORT")
    [ -z "$app_port" ] && app_port="3000"

    local protocol
    protocol=$(get_env_value_from_file "$ENV_FILE" "PROTOCOL")
    [ -z "$protocol" ] && protocol="http"

    local domain
    domain=$(get_env_value_from_file "$ENV_FILE" "DOMAIN")
    [ -z "$domain" ] && domain="localhost"

    local frontend_url
    frontend_url=$(get_env_value_from_file "$ENV_FILE" "FRONTEND_URL")
    if [ -z "$frontend_url" ]; then
        frontend_url="$protocol://$domain"
    fi

    local allowed_origins
    allowed_origins=$(get_env_value_from_file "$ENV_FILE" "ALLOWED_ORIGINS")
    if [ -z "$allowed_origins" ]; then
        allowed_origins=$(get_env_value_from_file "$ENV_FILE" "CORS_ORIGIN")
    fi
    if [ -z "$allowed_origins" ]; then
        allowed_origins="$frontend_url"
    fi

    local raw_mongo_uri
    raw_mongo_uri=$(get_env_value_from_file "$ENV_FILE" "MONGODB_URI")

    local mongo_db mongo_user mongo_pass mongo_port
    mongo_port=$(get_env_value_from_file "$ENV_FILE" "MONGO_PORT")
    [ -z "$mongo_port" ] && mongo_port="27017"

    if [ -n "$raw_mongo_uri" ]; then
        mongo_db=${raw_mongo_uri##*/}
        mongo_db=${mongo_db%%\?*}
        if [[ "$raw_mongo_uri" =~ mongodb://([^:@/]+):([^@/]+)@ ]]; then
            mongo_user="${BASH_REMATCH[1]}"
            mongo_pass="${BASH_REMATCH[2]}"
        fi
    fi

    [ -z "$mongo_db" ] && mongo_db=$(get_env_value_from_file "$ENV_FILE" "MONGO_INITDB_DATABASE")
    [ -z "$mongo_db" ] && mongo_db="ourverse"
    [ -z "$mongo_user" ] && mongo_user=$(get_env_value_from_file "$ENV_FILE" "MONGO_USERNAME")
    [ -z "$mongo_pass" ] && mongo_pass=$(get_env_value_from_file "$ENV_FILE" "MONGO_PASSWORD")
    [ -z "$mongo_user" ] && mongo_user="ourverse"
    [ -z "$mongo_pass" ] && mongo_pass="ourverse"

    local container_mongo_uri="mongodb://${mongo_user}:${mongo_pass}@mongodb:27017/${mongo_db}?authSource=admin"

    set_env_value "$ENV_FILE" "NODE_ENV" "production"
    set_env_value "$ENV_FILE" "HOST" "0.0.0.0"
    set_env_value "$ENV_FILE" "PORT" "$app_port"
    set_env_value "$ENV_FILE" "APP_PORT" "$app_port"
    set_env_value "$ENV_FILE" "ALLOWED_ORIGINS" "$allowed_origins"
    set_env_value "$ENV_FILE" "FRONTEND_URL" "$frontend_url"
    set_env_value "$ENV_FILE" "PROTOCOL" "$protocol"
    set_env_value "$ENV_FILE" "DOMAIN" "$domain"
    set_env_value "$ENV_FILE" "UPLOADS_DIR" "uploads"
    set_env_value "$ENV_FILE" "MONGO_USERNAME" "$mongo_user"
    set_env_value "$ENV_FILE" "MONGO_PASSWORD" "$mongo_pass"
    set_env_value "$ENV_FILE" "MONGO_PORT" "$mongo_port"
    set_env_value "$ENV_FILE" "MONGO_INITDB_DATABASE" "$mongo_db"
    set_env_value "$ENV_FILE" "MONGODB_URI_ORIGINAL" "$raw_mongo_uri"
    set_env_value "$ENV_FILE" "MONGODB_URI" "$container_mongo_uri"

    if ! grep -q "^SESSION_SECRET=" "$ENV_FILE" || [ -z "$(get_env_value_from_file "$ENV_FILE" "SESSION_SECRET")" ]; then
        local jwt_secret
        jwt_secret=$(get_env_value_from_file "$ENV_FILE" "JWT_SECRET")
        [ -z "$jwt_secret" ] && jwt_secret=$(openssl rand -hex 32)
        set_env_value "$ENV_FILE" "SESSION_SECRET" "$jwt_secret"
    fi

    rm -f "$ENV_FILE.bak"
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
