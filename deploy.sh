#!/bin/bash

# OurVerse 自动部署脚本

set -e

echo "🚀 开始 OurVerse 部署..."

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查必要工具
check_requirements() {
    echo -e "${YELLOW}🔍 检查系统要求...${NC}"
    
    local requirements=("docker" "docker-compose" "node" "npm")
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
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            echo -e "${GREEN}✅ 已创建 .env 文件，请编辑配置${NC}"
        else
            echo -e "${RED}❌ 未找到 .env.example 文件${NC}"
            exit 1
        fi
    fi
    
    # 生成强密码JWT密钥
    if ! grep -q "JWT_SECRET=.*[a-zA-Z0-9]{32}" .env; then
        local jwt_secret=$(openssl rand -hex 32)
        sed -i.bak "s/JWT_SECRET=.*/JWT_SECRET=$jwt_secret/" .env
        echo -e "${GREEN}✅ 已生成安全的JWT密钥${NC}"
    fi
}

# 构建应用
build_application() {
    echo -e "${YELLOW}🔨 构建应用...${NC}"
    
    # 安装依赖
    npm install
    
    # 构建前端（如果有构建脚本）
    if [ -f package.json ] && grep -q "build" package.json; then
        npm run build
    fi
    
    echo -e "${GREEN}✅ 应用构建完成${NC}"
}

# 启动服务
start_services() {
    echo -e "${YELLOW}🐳 启动Docker服务...${NC}"
    
    # 停止现有服务
    docker-compose down 2>/dev/null || true
    
    # 构建和启动
    docker-compose up -d --build
    
    # 等待服务启动
    echo -e "${YELLOW}⏳ 等待服务启动...${NC}"
    for i in {1..30}; do
        if docker-compose ps | grep -q "Up"; then
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
        echo -e "${YELLOW}查看日志: docker-compose logs${NC}"
        exit 1
    fi
}

# 部署完成信息
deployment_info() {
    local app_port=${DOCKER_APP_PORT:-3000}
    local nginx_http_port=${DOCKER_NGINX_HTTP_PORT:-80}
    local nginx_https_port=${DOCKER_NGINX_HTTPS_PORT:-443}
    local domain=${DOMAIN:-your-domain.com}
    local protocol=${PROTOCOL:-https}

    echo -e "${GREEN}🎉 部署完成！${NC}"
    echo ""
    echo -e "${GREEN}📍 访问地址:${NC}"
    echo -e "   本地访问: http://localhost:${nginx_http_port}"
    echo -e "   HTTPS访问: ${protocol}://${domain}:${nginx_https_port}"
    echo -e "   API地址: http://localhost:${app_port}"
    echo ""
    echo -e "${YELLOW}🔧 GitHub OAuth配置说明:${NC}"
    echo -e "   1. 在GitHub上创建OAuth应用"
    echo -e "   2. Homepage URL: ${protocol}://${domain}"
    echo -e "   3. Authorization callback URL: ${protocol}://${domain}/api/auth/github/callback"
    echo -e "   4. 更新.env文件中的DOMAIN、PROTOCOL和GITHUB_CALLBACK_URL"
    echo ""
    echo -e "${GREEN}📱 移动端访问:${NC}"
    echo -e "   ${protocol}://${domain}:${nginx_https_port}"
    echo ""
    echo -e "${GREEN}🛠️  常用命令:${NC}"
    echo -e "   查看日志: docker-compose logs -f"
    echo -e "   停止服务: docker-compose down"
    echo -e "   重启服务: docker-compose restart"
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
