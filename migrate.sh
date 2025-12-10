#!/bin/bash

# OurVerse 全量迁移脚本
# 功能：从A服务器迁移到B服务器（包括代码、数据库、上传文件等）
# 用法：
#   在A服务器执行: ./migrate.sh backup <backup_dir>
#   在B服务器执行: ./migrate.sh restore <backup_dir> [source_server]
#   在B服务器执行: ./migrate.sh migrate <source_server> <source_user> [source_key]

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
PROJECT_DIR="/home/ubuntu/OurVerse"

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

# 函数：检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

# 函数：在A服务器上备份数据
backup_data() {
    local backup_dir="${1:-/tmp/ourverse_backup_$(date +%Y%m%d_%H%M%S)}"
    local source_dir="${PROJECT_DIR:-$PROJECT_ROOT}"
    
    log_info "开始备份数据到: $backup_dir"
    log_info "源目录: $source_dir"
    
    mkdir -p "$backup_dir"
    
    # 备份代码（排除node_modules、logs等）
    log_info "备份项目代码..."
    mkdir -p "$backup_dir/code"
    rsync -av --exclude='node_modules' \
             --exclude='.git' \
             --exclude='*.log' \
             --exclude='server.log' \
             --exclude='backend/logs' \
             --exclude='backend/uploads' \
             --exclude='.env' \
             "$source_dir/" "$backup_dir/code/"
    
    # 备份.env文件
    if [ -f "$source_dir/.env" ]; then
        log_info "备份.env配置文件..."
        cp "$source_dir/.env" "$backup_dir/.env"
    elif [ -f "$source_dir/backend/.env" ]; then
        cp "$source_dir/backend/.env" "$backup_dir/.env"
    else
        log_warn ".env文件不存在，请确保手动备份"
    fi
    
    # 备份上传文件
    if [ -d "$source_dir/backend/uploads" ]; then
        log_info "备份上传文件..."
        mkdir -p "$backup_dir/uploads"
        rsync -av "$source_dir/backend/uploads/" "$backup_dir/uploads/"
    else
        log_warn "uploads目录不存在"
    fi
    
    # 备份MongoDB数据
    log_info "备份MongoDB数据..."
    mkdir -p "$backup_dir/mongodb"
    
    # 检查MongoDB是否运行
    if docker ps | grep -q ourverse-mongodb; then
        log_info "从Docker容器导出MongoDB数据..."
        
        # 获取MongoDB连接信息
        local mongo_user="${MONGO_USERNAME:-ourverse}"
        local mongo_pass="${MONGO_PASSWORD:-ourverse}"
        local mongo_db="${MONGO_INITDB_DATABASE:-ourverse}"
        
        # 导出数据库
        docker exec ourverse-mongodb mongodump \
            --username="$mongo_user" \
            --password="$mongo_pass" \
            --authenticationDatabase=admin \
            --db="$mongo_db" \
            --out=/tmp/mongodb_dump
        
        # 复制导出文件
        docker cp ourverse-mongodb:/tmp/mongodb_dump "$backup_dir/mongodb/"
        docker exec ourverse-mongodb rm -rf /tmp/mongodb_dump
        
        log_info "MongoDB数据备份完成"
    else
        log_warn "MongoDB容器未运行，尝试从Docker volume备份..."
        
        # 尝试从volume备份
        if docker volume ls | grep -q ourverse.*mongodb_data; then
            local volume_name=$(docker volume ls | grep ourverse.*mongodb_data | awk '{print $2}')
            docker run --rm \
                -v "$volume_name":/data/db:ro \
                -v "$backup_dir/mongodb":/backup \
                mongo:6.0 \
                tar czf /backup/mongodb_data.tar.gz -C /data/db .
            log_info "MongoDB volume备份完成"
        else
            log_error "无法找到MongoDB数据，请手动备份"
        fi
    fi
    
    # 创建备份信息文件
    cat > "$backup_dir/backup_info.txt" <<EOF
备份时间: $(date)
项目路径: $source_dir
MongoDB用户: ${MONGO_USERNAME:-ourverse}
MongoDB数据库: ${MONGO_INITDB_DATABASE:-ourverse}
Node版本: $(node --version 2>/dev/null || echo "未安装")
Docker版本: $(docker --version 2>/dev/null || echo "未安装")
EOF
    
    log_info "备份完成！备份目录: $backup_dir"
    log_info "请将此目录传输到B服务器"
}

# 函数：在B服务器上安装依赖
install_dependencies() {
    log_info "检查并安装系统依赖..."
    
    # 检查Node.js
    if ! check_command node; then
        log_info "安装Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -lt 16 ]; then
            log_warn "Node.js版本过低，需要升级..."
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt-get install -y nodejs
        else
            log_info "Node.js已安装: $(node --version)"
        fi
    fi
    
    # 检查npm
    if ! check_command npm; then
        log_error "npm未安装，请检查Node.js安装"
        exit 1
    fi
    
    # 检查Docker
    if ! check_command docker; then
        log_info "安装Docker..."
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sudo sh /tmp/get-docker.sh
        sudo usermod -aG docker $USER
        rm /tmp/get-docker.sh
        log_warn "Docker已安装，请重新登录或执行: newgrp docker"
    else
        log_info "Docker已安装: $(docker --version)"
    fi
    
    # 检查Docker Compose
    if ! check_command docker-compose; then
        log_info "安装Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    else
        log_info "Docker Compose已安装: $(docker-compose --version)"
    fi
    
    # 检查nginx
    if ! check_command nginx; then
        log_info "安装nginx..."
        sudo apt-get update
        sudo apt-get install -y nginx
    else
        log_info "nginx已安装: $(nginx -v 2>&1)"
    fi
    
    log_info "依赖检查完成"
}

# 函数：从A服务器拉取数据
pull_from_source() {
    local source_server="$1"
    local source_user="${2:-ubuntu}"
    local source_key="${3:-}"
    local backup_dir="${4:-/tmp/ourverse_backup_$(date +%Y%m%d_%H%M%S)}"
    
    log_info "从A服务器 ($source_server) 拉取数据..."
    
    # 在A服务器上执行备份
    local ssh_cmd="ssh"
    if [ -n "$source_key" ]; then
        ssh_cmd="$ssh_cmd -i $source_key"
    fi
    ssh_cmd="$ssh_cmd $source_user@$source_server"
    
    # 在A服务器上创建备份
    local remote_backup="/tmp/ourverse_backup_remote_$(date +%Y%m%d_%H%M%S)"
    log_info "在A服务器上创建备份..."
    $ssh_cmd "cd $PROJECT_DIR && bash migrate.sh backup $remote_backup" || {
        log_error "在A服务器上备份失败"
        exit 1
    }
    
    # 拉取备份文件
    log_info "拉取备份文件..."
    mkdir -p "$backup_dir"
    
    if [ -n "$source_key" ]; then
        rsync -avz --progress -e "ssh -i $source_key" "$source_user@$source_server:$remote_backup/" "$backup_dir/"
    else
        rsync -avz --progress "$source_user@$source_server:$remote_backup/" "$backup_dir/"
    fi
    
    # 清理A服务器上的临时备份
    log_info "清理A服务器上的临时备份..."
    $ssh_cmd "rm -rf $remote_backup"
    
    log_info "数据拉取完成: $backup_dir"
    echo "$backup_dir"
}

# 函数：在B服务器上恢复数据
restore_data() {
    local backup_dir="$1"
    
    if [ ! -d "$backup_dir" ]; then
        log_error "备份目录不存在: $backup_dir"
        exit 1
    fi
    
    log_info "开始恢复数据从: $backup_dir"
    
    # 创建项目目录
    log_info "创建项目目录..."
    sudo mkdir -p "$PROJECT_DIR"
    sudo chown -R $USER:$USER "$PROJECT_DIR"
    
    # 恢复代码
    log_info "恢复项目代码..."
    if [ -d "$backup_dir/code" ]; then
        rsync -av "$backup_dir/code/" "$PROJECT_DIR/"
    else
        log_error "代码备份不存在"
        exit 1
    fi
    
    # 恢复.env文件
    if [ -f "$backup_dir/.env" ]; then
        log_info "恢复.env配置文件..."
        cp "$backup_dir/.env" "$PROJECT_DIR/.env"
    else
        log_warn ".env文件不存在，请手动配置"
    fi
    
    # 恢复上传文件
    if [ -d "$backup_dir/uploads" ]; then
        log_info "恢复上传文件..."
        mkdir -p "$PROJECT_DIR/backend/uploads"
        rsync -av "$backup_dir/uploads/" "$PROJECT_DIR/backend/uploads/"
    fi
    
    # 安装npm依赖
    log_info "安装npm依赖..."
    cd "$PROJECT_DIR/backend"
    npm install --production
    
    # 恢复MongoDB数据
    log_info "恢复MongoDB数据..."
    
    # 先启动MongoDB容器
    if ! docker ps -a | grep -q ourverse-mongodb; then
        log_info "创建MongoDB容器..."
        docker run -d --name ourverse-mongodb \
            -p 27017:27017 \
            -e MONGO_INITDB_ROOT_USERNAME=ourverse \
            -e MONGO_INITDB_ROOT_PASSWORD=ourverse \
            mongo:6.0
        sleep 5
    else
        log_info "启动MongoDB容器..."
        docker start ourverse-mongodb
        sleep 5
    fi
    
    # 等待MongoDB就绪
    log_info "等待MongoDB就绪..."
    for i in {1..30}; do
        if docker exec ourverse-mongodb mongosh --quiet --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    # 恢复数据库
    if [ -d "$backup_dir/mongodb/mongodb_dump" ]; then
        log_info "恢复MongoDB数据库..."
        
        # 读取备份信息获取数据库名
        local mongo_db="ourverse"
        if [ -f "$backup_dir/backup_info.txt" ]; then
            local db_from_info=$(grep "MongoDB数据库" "$backup_dir/backup_info.txt" | cut -d: -f2 | tr -d ' ')
            if [ -n "$db_from_info" ]; then
                mongo_db="$db_from_info"
            fi
        fi
        
        # 检查dump目录结构
        local dump_path="$backup_dir/mongodb/mongodb_dump"
        if [ -d "$dump_path/$mongo_db" ]; then
            dump_path="$dump_path/$mongo_db"
        fi
        
        # 复制dump文件到容器
        docker cp "$backup_dir/mongodb/mongodb_dump" ourverse-mongodb:/tmp/mongodb_dump
        
        # 恢复数据库（使用--drop选项覆盖现有数据）
        docker exec ourverse-mongodb mongorestore \
            --username=ourverse \
            --password=ourverse \
            --authenticationDatabase=admin \
            --drop \
            /tmp/mongodb_dump
        
        # 清理
        docker exec ourverse-mongodb rm -rf /tmp/mongodb_dump
        
        log_info "MongoDB数据恢复完成"
    elif [ -f "$backup_dir/mongodb/mongodb_data.tar.gz" ]; then
        log_warn "检测到volume备份，需要手动恢复MongoDB数据"
        log_warn "备份文件: $backup_dir/mongodb/mongodb_data.tar.gz"
    else
        log_warn "未找到MongoDB备份数据"
    fi
    
    # 配置nginx
    log_info "配置nginx..."
    if [ -f "$PROJECT_DIR/infra/nginx.conf" ]; then
        sudo cp "$PROJECT_DIR/infra/nginx.conf" /etc/nginx/sites-available/ourverse
        if [ ! -f /etc/nginx/sites-enabled/ourverse ]; then
            sudo ln -s /etc/nginx/sites-available/ourverse /etc/nginx/sites-enabled/
        fi
        sudo nginx -t && sudo systemctl reload nginx || log_warn "nginx配置测试失败，请手动检查"
    else
        log_warn "nginx配置文件不存在"
    fi
    
    log_info "数据恢复完成！"
    log_info "项目目录: $PROJECT_DIR"
    log_info "请检查.env配置文件，然后运行: cd $PROJECT_DIR && ./ourverse.sh start"
}

# 函数：一键迁移（从A服务器拉取并恢复）
migrate_from_source() {
    local source_server="$1"
    local source_user="${2:-ubuntu}"
    local source_key="${3:-}"
    
    log_info "开始一键迁移流程..."
    log_info "源服务器: $source_server"
    log_info "源用户: $source_user"
    
    # 安装依赖
    install_dependencies
    
    # 从A服务器拉取数据
    local backup_dir=$(pull_from_source "$source_server" "$source_user" "$source_key")
    
    # 恢复数据
    restore_data "$backup_dir"
    
    log_info "迁移完成！"
    log_info "下一步:"
    log_info "  1. 检查并编辑 $PROJECT_DIR/.env"
    log_info "  2. 运行: cd $PROJECT_DIR && ./ourverse.sh start"
}

# 主逻辑
case "${1:-}" in
    "backup")
        backup_data "${2:-}"
        ;;
    "restore")
        if [ -z "$2" ]; then
            log_error "请指定备份目录"
            echo "用法: $0 restore <backup_dir>"
            exit 1
        fi
        install_dependencies
        restore_data "$2"
        ;;
    "migrate")
        if [ -z "$2" ]; then
            log_error "请指定源服务器地址"
            echo "用法: $0 migrate <source_server> [source_user] [source_key]"
            exit 1
        fi
        migrate_from_source "$2" "${3:-ubuntu}" "${4:-}"
        ;;
    "install")
        install_dependencies
        ;;
    *)
        echo "OurVerse 迁移脚本"
        echo ""
        echo "用法:"
        echo "  在A服务器上备份:"
        echo "    $0 backup [backup_dir]"
        echo ""
        echo "  在B服务器上恢复:"
        echo "    $0 restore <backup_dir>"
        echo ""
        echo "  在B服务器上一键迁移（从A服务器拉取）:"
        echo "    $0 migrate <source_server> [source_user] [source_key]"
        echo ""
        echo "  仅安装依赖:"
        echo "    $0 install"
        echo ""
        echo "示例:"
        echo "  # A服务器备份"
        echo "  ./migrate.sh backup /tmp/my_backup"
        echo ""
        echo "  # B服务器恢复（已传输备份）"
        echo "  ./migrate.sh restore /tmp/my_backup"
        echo ""
        echo "  # B服务器一键迁移（自动从A拉取）"
        echo "  ./migrate.sh migrate 192.168.1.100 ubuntu ~/.ssh/id_rsa"
        exit 1
        ;;
esac

