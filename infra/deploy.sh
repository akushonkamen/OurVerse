#!/bin/bash

# OurVerse 自动部署脚本

set -e

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BACKEND_DIR="$PROJECT_ROOT/backend"
COMPOSE_FILE="$PROJECT_ROOT/infra/docker-compose.yml"
ENV_FILE="$PROJECT_ROOT/.env"

if command -v docker compose >/dev/null 2>&1; then
    COMPOSE_BIN="docker compose -f $COMPOSE_FILE"
    compose() {
        docker compose -f "$COMPOSE_FILE" "$@"
    }
else
    COMPOSE_BIN="docker-compose -f $COMPOSE_FILE"
    compose() {
        docker-compose -f "$COMPOSE_FILE" "$@"
    }
fi

echo "🚀 开始 OurVerse 部署..."

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 工具函数
escape_sed() {
    printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

get_env_value() {
    local key="$1"
    if [ -f "$ENV_FILE" ]; then
        grep -E "^${key}=" "$ENV_FILE" | tail -n1 | cut -d= -f2-
    fi
}

set_env_value() {
    local key="$1"
    local value="$2"
    local escaped_value
    escaped_value=$(escape_sed "$value")

    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i.bak "s|^${key}=.*|${key}=${escaped_value}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

ensure_env_default() {
    local key="$1"
    local default_value="$2"
    local current
    current=$(get_env_value "$key")
    if [ -z "$current" ]; then
        set_env_value "$key" "$default_value"
    fi
}

# 检查必要工具
check_requirements() {
    echo -e "${YELLOW}🔍 检查系统要求...${NC}"
    
    local requirements=("docker" "node" "npm" "openssl")
    for req in "${requirements[@]}"; do
        if ! command -v "$req" &> /dev/null; then
            echo -e "${RED}❌ 缺少 $req，请先安装${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}✅ 系统要求检查通过${NC}"
}

# 环境配置
setup_environment() {
    echo -e "${YELLOW}⚙️  配置环境...${NC}"
    
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "$BACKEND_DIR/.env.example" ]; then
            cp "$BACKEND_DIR/.env.example" "$ENV_FILE"
            echo -e "${GREEN}✅ 已创建 .env 文件，请编辑配置${NC}"
        else
            echo -e "${RED}❌ 未找到 .env.example 文件${NC}"
            exit 1
        fi
    fi

    ensure_env_default "MONGO_USERNAME" "ourverse"
    ensure_env_default "MONGO_PASSWORD" "ourverse"
    ensure_env_default "MONGO_PORT" "27017"
    ensure_env_default "MONGO_INITDB_DATABASE" "ourverse"
    ensure_env_default "APP_PORT" "3000"

    local app_port
    app_port=$(get_env_value "APP_PORT")
    if [ -z "$app_port" ]; then
        app_port="3000"
    fi

    if [ -z "$(get_env_value "PORT")" ]; then
        set_env_value "PORT" "$app_port"
    fi

    ensure_env_default "UPLOADS_DIR" "uploads"

    local default_origin="http://localhost:${app_port}"
    if [ -z "$(get_env_value "ALLOWED_ORIGINS")" ]; then
        set_env_value "ALLOWED_ORIGINS" "$default_origin"
    fi
    if [ -z "$(get_env_value "FRONTEND_URL")" ]; then
        set_env_value "FRONTEND_URL" "$default_origin"
    fi

    local mongo_username mongo_password mongo_database
    mongo_username=$(get_env_value "MONGO_USERNAME")
    mongo_password=$(get_env_value "MONGO_PASSWORD")
    mongo_database=$(get_env_value "MONGO_INITDB_DATABASE")

    if [ -z "$mongo_username" ]; then
        mongo_username="ourverse"
    fi
    if [ -z "$mongo_password" ]; then
        mongo_password="ourverse"
    fi
    if [ -z "$mongo_database" ]; then
        mongo_database="ourverse"
    fi

    local default_uri="mongodb://${mongo_username}:${mongo_password}@mongodb:27017/${mongo_database}?authSource=admin"
    ensure_env_default "MONGODB_URI" "$default_uri"
    
    # 生成强密码JWT密钥
    if ! grep -q "^JWT_SECRET=.*[a-zA-Z0-9]\{32\}" "$ENV_FILE"; then
        local jwt_secret=$(openssl rand -hex 32)
        if grep -q '^JWT_SECRET=' "$ENV_FILE"; then
            set_env_value "JWT_SECRET" "$jwt_secret"
        else
            set_env_value "JWT_SECRET" "$jwt_secret"
        fi
        echo -e "${GREEN}✅ 已生成安全的JWT密钥${NC}"
    fi

    local jwt_secret_value
    jwt_secret_value=$(get_env_value "JWT_SECRET")
    if [ -z "$jwt_secret_value" ]; then
        jwt_secret_value=$(openssl rand -hex 32)
        set_env_value "JWT_SECRET" "$jwt_secret_value"
    fi

    if [ -z "$(get_env_value "SESSION_SECRET")" ]; then
        set_env_value "SESSION_SECRET" "$jwt_secret_value"
        echo -e "${GREEN}✅ SESSION_SECRET 已同步为 JWT_SECRET${NC}"
    fi

    rm -f "$ENV_FILE.bak"
}

# 构建应用
build_application() {
    echo -e "${YELLOW}🔨 构建应用...${NC}"
    
    # 安装依赖
    npm install --prefix "$BACKEND_DIR"
    
    echo -e "${GREEN}✅ 应用构建完成${NC}"
}

# 启动服务
start_services() {
    echo -e "${YELLOW}🐳 启动Docker服务...${NC}"
    
    # 停止现有服务
    compose down 2>/dev/null || true
    
    # 构建和启动
    compose up -d --build
    
    # 等待服务启动
    echo -e "${YELLOW}⏳ 等待服务启动...${NC}"
    for i in {1..30}; do
        if compose ps | grep -q "Up"; then
            break
        fi
        sleep 2
    done
    
    echo -e "${GREEN}✅ 服务启动完成${NC}"
}

# 健康检查
health_check() {
    echo -e "${YELLOW}🔍 执行健康检查...${NC}"
    
    # 检查API健康状态
    local max_attempts=10
    local attempt=1
    local health_port=${HEALTH_CHECK_PORT:-3000}

    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:${health_port}/health &>/dev/null; then
            echo -e "${GREEN}✅ API 服务健康${NC}"
            break
        fi

        echo -e "${YELLOW}等待API启动... (尝试 $attempt/$max_attempts)${NC}"
        sleep 5
        ((attempt++))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        echo -e "${RED}❌ API 服务未能正常启动${NC}"
        echo -e "${YELLOW}查看日志: $COMPOSE_BIN logs ${NC}"
        exit 1
    fi
}

# 部署完成信息
deployment_info() {
    local app_port=$(get_env_value "APP_PORT")
    local mongo_port=$(get_env_value "MONGO_PORT")
    local domain=${DOMAIN:-your-domain.com}
    local protocol=${PROTOCOL:-https}
    local mongo_username=$(get_env_value "MONGO_USERNAME")
    local mongo_password=$(get_env_value "MONGO_PASSWORD")
    local mongo_database=$(get_env_value "MONGO_INITDB_DATABASE")

    echo -e "${GREEN}🎉 部署完成！${NC}"
    echo ""
    echo -e "${GREEN}📍 访问地址:${NC}"
    echo -e "   API: http://localhost:${app_port}"
    echo -e "   生产可配置: ${protocol}://${domain}:${app_port}"
    echo ""
    echo -e "${YELLOW}🔧 GitHub OAuth配置说明:${NC}"
    echo -e "   1. 在GitHub上创建OAuth应用"
    echo -e "   2. Homepage URL: ${protocol}://${domain}"
    echo -e "   3. Authorization callback URL: ${protocol}://${domain}/api/auth/github/callback"
    echo -e "   4. 更新.env文件中的DOMAIN、PROTOCOL和GITHUB_CALLBACK_URL"
    echo ""
    echo -e "${GREEN}🍃 MongoDB 连接信息:${NC}"
    echo -e "   URI: mongodb://${mongo_username}:${mongo_password}@localhost:${mongo_port}/${mongo_database}?authSource=admin"
    echo -e "   远程容器: mongodb://$mongo_username:$mongo_password@mongodb:27017/${mongo_database}?authSource=admin"
    echo ""
    echo -e "${GREEN}🛠️  常用命令:${NC}"
    echo -e "   查看日志: $COMPOSE_BIN logs -f"
    echo -e "   停止服务: $COMPOSE_BIN down"
    echo -e "   重启服务: $COMPOSE_BIN restart"
    echo -e "   更新部署: $0"
    echo ""
    echo -e "${YELLOW}⚠️  安全提醒:${NC}"
    echo -e "   1. 请尽快配置真实的域名和SSL证书"
    echo -e "   2. 在生产环境中使用强密码"
    echo -e "   3. 定期备份数据库数据"
    echo ""
}

# 主函数
main() {
    echo -e "${GREEN}🚀 OurVerse 自动部署脚本${NC}"
    echo ""
    
    check_requirements
    setup_environment
    build_application
    start_services
    health_check
    deployment_info
    
    echo -e "${GREEN}✅ 部署成功完成！${NC}"
}

# 运行主函数
main "$@"
