# 部署指南

本目录包含部署 OurVerse 后端所需的 Docker / Railway 配置与辅助脚本。

- `docker-compose.yml`：本地或服务器上的容器编排文件，构建上下文已指向 `../backend`。
- `deploy.sh`：一键部署脚本，会自动安装依赖、拉起 Docker 服务并执行健康检查。
- `railway.toml`：Railway 平台的项目配置，使用 `../backend/Dockerfile` 作为镜像构建入口。
- `mongo-init/`：MongoDB 初始化脚本，随 Docker Compose 自动挂载。

## 常用命令

```bash
./infra/deploy.sh            # 触发完整部署流程
./infra/deploy.sh --help     # 查看可用参数（如需扩展，可在脚本中添加）

# 直接使用 Docker Compose
docker compose -f infra/docker-compose.yml up -d --build
```

部署完成后，后端 API 会按 `.env` 中的设置监听端口，保持与小程序配置的 API 地址一致即可。
