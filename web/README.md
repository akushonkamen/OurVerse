# OUTIE 网页前端

OUTIE 的网页客户端（单文件 `index.html`，无构建、无依赖）。
像素宠物 + 线下打卡收集：领养起名 → 到活动点位打卡（200 米围栏校验）→ 收集造型 → 集齐解锁限定形态 → 现场拍照合成。

## 本地运行

```bash
# 任意静态服务器即可，例如：
python3 -m http.server 8642
# 打开 http://127.0.0.1:8642/
```

后端为本仓库 `backend/`（outie 模块：`/api/outie/*`）。前端默认连
`http://127.0.0.1:8444`，如需指向其他环境：

```js
localStorage.setItem('outie.api-base', 'https://your-api-host');
```

连不上后端时自动回退为离线演示模式（进度仅存本地浏览器）。

## 说明

- 身份：匿名（`x-anonymous-id`），可选绑定账号（沿用后端既有账号体系）
- 打卡校验：服务端 200 米围栏；开发环境可设 `OUTIE_DEV_SKIP_GEO=true` 跳过
- 地图：高德 JS API（key 走 `/api/outie/amap-config` 下发），加载失败回退手绘示意图
- 活动数据：`node scripts/seed-outie-demo.js` 写入演示活动 WEEKEND.EXE（幂等）
