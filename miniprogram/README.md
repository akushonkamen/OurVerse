# OUTIE 步数小程序（伴生端）
用微信开发者工具导入本目录 → 填入你的 AppID（project.config.json）→ 预览/上传。
后端需配置 WX_APPID / WX_SECRET（backend/.env），并将 https://our-verse.com 加入小程序后台 request 合法域名（需 ICP 备案）。
流程：用户在 H5「我的」页生成 6 位绑定码 → 小程序输入绑定 → 每日点「同步微信运动步数」入账。
