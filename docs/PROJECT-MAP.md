# OUTIE 项目全景图（架构 · 资产 · 遗留）

2026-09-28 梳理。本仓库是唯一产品仓库：**OUTIE**（像素宠物 + 线下打卡收集），
由原 OurVerse 后端作为引擎（地点、围栏打卡、照片流、身份）。

## 一、目录结构总览

| 路径 | 是什么 | 状态 |
| --- | --- | --- |
| `backend/src/` | Node/Express + Mongoose 服务端 | **核心，活跃** |
| `backend/src/services/outie-service.js` | OUTIE 业务逻辑（活动/宠物/围栏打卡/合成照/地图） | **核心，活跃** |
| `backend/src/controllers/outie-controller.js` | `/api/outie/*` 薄控制层（解析请求 → 调 service） | **核心，活跃** |
| `backend/src/models/outie-*.js` | OutieEvent / OutiePet 数据模型 | **核心，活跃** |
| `backend/src/routes/outie-routes.js` | `/api/outie/*` 路由 | **核心，活跃** |
| `backend/scripts/seed-outie-demo.js` | 演示活动种子脚本（幂等；`npm` 环境下手动跑） | 活跃。另：后端启动时若 `outie_events` 为空会自动补种演示活动；`OUTIE_AUTOSEED=true` 可强制刷新 | 活跃 |
| `web/index.html` | OUTIE 网页前端（单文件，无构建） | **核心，活跃** |
| `backend/src/{auth,photo,bar,location}-*` | 原 OurVerse 能力：账号、照片流、酒吧、定位 | 活跃（作为引擎能力） |
| `backend/public/website.html` | 旧 OurVerse 官网 | **遗留**，仅 `/website.html` 可达 |
| `ios/OurVerse/` | 旧 OurVerse SwiftUI App | **遗留**，待按 OUTIE 重做（Phase 3） |
| `infra/` | docker-compose（Mongo+API）、nginx.conf | 部署用 |
| `ourverse.sh` / `migrate*.sh` / `fix-nginx.sh` | 生产运维/一次性迁移脚本 | 保留，勿随意执行 |
| `server.js`（根） | 仅 `require('./backend/server')` 转发入口 | 保留（Railway 兼容） |

## 二、后端 API 一览

### OUTIE 产品接口（`/api/outie`，前端 `web/index.html` 使用）

| 端点 | 鉴权 | 用途 |
| --- | --- | --- |
| `GET /event/current` | 公开 | 当前活动 + 点位 + `devSkipGeo` 标志 |
| `POST /pet` `{name}` | 匿名/登录 | 创建或更新宠物（幂等） |
| `GET /me` | 匿名/登录 | 宠物完整状态（造型/穿戴/进化） |
| `POST /checkin` `{spotKey,userLng,userLat}` | 匿名/登录 | 打卡：围栏校验 → 发造型 → 集齐自动进化（幂等） |
| `POST /composites` | 匿名/登录 | 上传宠物合成照 |
| `GET /staticmap` | 公开 | 高德静态图代理（服务端拉流直出图片字节，key 不出服务端） |
| `GET /amap-config` | 公开 | 下发 JS key + securityCode |

### 引擎接口（原 OurVerse，前端「现场」页与未来 App 复用）

| 模块 | 端点 | 备注 |
| --- | --- | --- |
| auth | register / login / verify / github(+callback) | JWT + GitHub OAuth |
| photos | upload / nearby / my / anonymous(+my,delete) / :id / :id/comments | 照片流；匿名上传限额 1 张/天 |
| bars | POST /checkin（200m 围栏）/ GET :amapPoiId/checkins | 旧"酒吧打卡"，与 OUTIE 打卡并存 |
| location | /ip /regeo | 高德定位 |
| config | /amap/config | 旧配置端点 |

## 三、数据模型

| 模型 | 关键字段 | 关系 |
| --- | --- | --- |
| `OutieEvent` | key, name, active, spots[{key,zone,rewardName,lookId,amapPoiId,address,lng,lat,radiusMeters}] | spot 是打卡目标，可绑定高德真实地点 |
| `OutiePet` | identityKey(索引), name, rewards{eventKey:{spotKey:Date}}, evolvedEvents[eventKey], equipped | **宠物跨活动存在**（2026-09-28 重构）；identityKey = `a:<匿名id>` 或 `u:<用户id>`，登录时匿名宠物自动过户 |
| `Bar` | amapPoiId, name, lng/lat, checkins[]（内嵌） | 旧打卡数据，冷启动城市内容 |
| `Photo` | url, lat/lng, caption, owner/anonymous | 「现场」照片流；合成照也走这里 |
| `User` | username, avatar, github 绑定 | 可选绑定，匿名优先 |

## 四、前端（web/index.html）

- 单文件、无构建：HTML+CSS+JS 全内联；设计系统 = 纸底 `#efecdf` + 墨 `#26241c` + 蓝红黄绿四点缀色，
  2px 硬边框、无圆角无阴影、`steps()` 跳帧动画、点阵字 `pixText()`、像素宠物 `petSVG()`（22×16，5 形态）
- 四页签：我的宠物 / 去哪儿（高德 JS 纸感地图 + 像素标记）/ 现场（照片流）/ SET
- 身份：`x-anonymous-id` 头（localStorage 持久化）；API 地址可用 `localStorage['outie.api-base']` 覆盖
- 回退链：连不上后端 → 离线演示模式；高德失败 → 手绘示意图 + 角标

## 五、部署与运维

- 生产：nginx → `127.0.0.1:8444`（Node），MongoDB 独立；`ourverse.sh` 为生产重启辅助脚本
- 发布流程：push 到 GitHub → 服务器 `git pull` → 重启后端
- 环境变量集中在 `backend/.env`（不入库，模板见 `backend/.env.example`）；新增变量必须登记到 `src/config/env.js`
- 本地开发：mongo（brew/docker）+ `npm run dev`（8444）+ 任意静态服务器跑 `web/`

## 六、重叠与遗留（技术债清单）

1. **controller 已瘦身**：outie 业务逻辑已抽入 `services/outie-service.js`（`ServiceError` 统一错误），controller 只做解析与响应，符合 AGENTS.md 约定。
2. **两套打卡并存**：`Bar.checkins`（旧酒吧打卡）与 `OutiePet.rewards`（活动打卡）。
   处理策略：不动旧接口（iOS 与既有数据在用），产品层统一叫「地点」；
   未来 iOS 重做时全部切 `/api/outie`，届时再评估合并存储。
3. **命名不一致**：代码里 `bar` vs 产品里「地点/spot」。同上，先文档统一、后代码统一。
4. **`/website.html` 旧官网**：已从首页下线，保留可达；确认无流量后可删。
4. ~~staticmap 302 会把 key 带进 Location 头~~ **已解决（2026-09-28）**：改为服务端拉流，直接返回图片字节，key 不出服务端。
6. **配额**：高德静态图/JS 有日配额；匿名照片上传 1 张/天（`ANONYMOUS_DAILY_UPLOAD_LIMIT`）。上线前按量调整。
7. **高德域名白名单**：JS key 若绑域，需把生产域名加入控制台，否则地图退示意图。
8. **iOS App 与新产品脱节**：SwiftUI 壳仍是旧 OurVerse，Phase 3 重做。
9. **CORS 白名单手动维护**（`ALLOWED_ORIGINS`）：新增前端域记得同步。
10. 根目录 `node_modules/`（为根 `server.js` 转发入口而装）历史遗留，可在确认部署方式后清理。
11. ~~`backend/server.log` 被误入版本库~~ **已清理（2026-09-28）**：移出追踪并加入 .gitignore。

## 七、演进路线

- **Phase 2**：照片流与合成照深度打通（合成照带活动印章进流）、AI 生图合成灰度、活动配置结构化
  （主办方/日期/出处进入造型）
- **Phase 3**：iOS 壳按 OUTIE 设计系统重做；桌面小组件；相机直出合成
- **长期**：打卡存储统一、`bar`→`spot` 代码层重命名（配合 iOS 切换窗口）
