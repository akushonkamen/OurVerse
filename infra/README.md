# 部署指南

本目录包含部署 OurVerse 后端所需的 Docker / Railway 配置与辅助脚本。

- `docker-compose.yml`：编排 OurVerse API 与 MongoDB 的容器，默认端口与凭据可通过 `.env` 调整。
- `deploy.sh`：一键部署脚本，会生成 `.env`、填充密钥、构建镜像并拉起全部服务。
- `railway.toml`：Railway 平台的项目配置，使用 `../backend/Dockerfile` 作为镜像构建入口。
- `mongo-init/`：MongoDB 初始化脚本，随 Docker Compose 自动挂载。

## 常用命令

```bash
./infra/deploy.sh            # 推荐：一键部署并自动写入 .env

# 如果已经配置好 .env，可直接使用 Docker Compose
docker compose -f infra/docker-compose.yml up -d --build
```

部署完成后，后端 API 会按 `.env` 中的设置监听端口，保持与小程序配置的 API 地址一致即可。

## 关键环境变量

部署脚本会以 `backend/.env.example` 为模板生成根目录 `.env`，核心变量如下：

| 变量 | 作用 | 默认值 |
| --- | --- | --- |
| `APP_PORT` | 宿主暴露的 API 端口 | `3000` |
| `MONGO_PORT` | 宿主映射的 MongoDB 端口 | `27017` |
| `MONGO_USERNAME` / `MONGO_PASSWORD` | MongoDB root 账户 | `ourverse` / `ourverse` |
| `MONGODB_URI` | API 访问数据库的连接串 | `mongodb://ourverse:ourverse@mongodb:27017/ourverse?authSource=admin` |
| `JWT_SECRET` | 登录鉴权签名密钥 | 自动生成 |
| `SESSION_SECRET` | OAuth Session 密钥（默认沿用 `JWT_SECRET`） | 自动生成 |

如需启用 GitHub 登录或高德地图定位，请在 `.env` 中补齐 `GITHUB_*` 与 `AMAP_*` 相关配置。
