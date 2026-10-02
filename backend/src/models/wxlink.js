const mongoose = require('mongoose');

// 微信 openid ↔ OUTIE 身份 绑定关系（一个小程序号绑一个 OUTIE 身份）
const wxLinkSchema = new mongoose.Schema({
  openid: { type: String, required: true, unique: true },
  identityKey: { type: String, required: true, index: true },
  anonymousId: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('WxLink', wxLinkSchema);
