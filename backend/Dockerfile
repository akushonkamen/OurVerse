FROM node:18-alpine

# 安装安全更新和必要工具
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init curl && \
    rm -rf /var/cache/apk/*

# 创建应用用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S ourverse -u 1001 -G nodejs

# 设置工作目录
WORKDIR /app

# 复制package文件（利用Docker缓存层）
COPY package*.json ./

# 安装依赖
RUN npm ci --only=production && npm cache clean --force

# 复制应用代码
COPY --chown=ourverse:nodejs . .

# 创建必要的目录
RUN mkdir -p uploads logs && \
    chown -R ourverse:nodejs /app

# 切换到非root用户
USER ourverse

# 暴露端口（Railway会覆盖这个）
EXPOSE 3000

# 健康检查（确保健康检查脚本存在）
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3000}/health || exit 1

# 使用dumb-init启动应用（更好的信号处理）
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["npm", "start"]
