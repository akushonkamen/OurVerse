# OUTIE

把你参加过的线下活动，变成宠物身上可以展示的限定纪念。

到现场打卡 → 拿限定造型 → 给宠物换上 → 集齐三个地点，解锁活动限定形态。

本仓库是 OUTIE 的完整产品仓库：`web/` 网页前端、`backend/` 服务端（含 outie 模块与
原 OurVerse 引擎能力：地点、围栏打卡、照片流、身份）、`ios/`（待按 OUTIE 重做）、
`infra/` 部署配置。

> 历史说明：本仓库前身为 OurVerse（线下地点打卡 + 照片）。现作为 OUTIE 的引擎整合，
> 产品对外统一命名 **OUTIE**，旧官网保留在 `backend/public/website.html`（`/website.html`）。

## 快速开始

```bash
# 1. 后端（需本地 MongoDB；环境变量见 backend/.env.example）
cd backend && npm install
OUTIE_DEV_SKIP_GEO=true npm start        # http://127.0.0.1:8444

# 2. 演示活动数据（幂等）
node scripts/seed-outie-demo.js

# 3. 前端（web/ 单文件，任意静态服务器）
cd ../web && python3 -m http.server 8642 # http://127.0.0.1:8642
```

- 打卡围栏：服务端 200 米校验；本地开发设 `OUTIE_DEV_SKIP_GEO=true` 跳过
- 身份：匿名优先（`x-anonymous-id`），可选 GitHub 账号绑定
- 地图：高德 JS API，key 经 `/api/outie/amap-config` 下发；失败自动回退手绘示意图

## 文档

- [docs/PROJECT-MAP.md](docs/PROJECT-MAP.md) —— 架构总览、API/数据模型一览、技术债与路线
- [docs/INTEGRATION-PLAN.md](docs/INTEGRATION-PLAN.md) —— OurVerse → OUTIE 整合方案与执行状态

## 开发约定

见 [AGENTS.md](AGENTS.md)。要点：`backend/.env` 不入库；新增环境变量登记到
`src/config/env.js`；对旧 OurVerse 接口只做增量不破坏；前端为单文件、遵循墨水屏 8-bit 设计系统
（纸底/墨色/四点缀色、硬边框、steps 动效、点阵字与像素宠物）。
