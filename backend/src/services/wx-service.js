const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { ServiceError: SE } = require('./outie-service');
const WxLink = require('../models/wxlink');
const OutiePet = require('../models/outie-pet');
const dayKeyOf = () => {
  const t = new Date(Date.now() + 8 * 3600000);
  return t.toISOString().slice(0, 10);
};

// 微信小程序配置（env：WX_APPID / WX_SECRET，未配置则相关接口返回引导性错误）
const configured = () => Boolean(config.outie && config.outie.wx && config.outie.wx.appid && config.outie.wx.secret);
const wxConf = () => config.outie.wx;

// 绑定码：H5 生成 → 用户在小程序输入 → openid 绑定到该 OUTIE 身份（进程内 TTL 10 分钟）
const bindCodes = new Map(); // code -> { identityKey, anonymousId, expiresAt }
const genBindCode = identity => {
  const code = String(crypto.randomInt(100000, 999999));
  bindCodes.set(code, { identityKey: identity.identityKey, anonymousId: identity.anonymousId || '', expiresAt: Date.now() + 10 * 60000 });
  return { code, expiresIn: 600 };
};
const takeBindCode = code => {
  const rec = bindCodes.get(String(code));
  if (!rec || rec.expiresAt < Date.now()) return null;
  bindCodes.delete(String(code));
  return rec;
};

// wx.login code → openid + session_key；签发无状态 wxToken（携带 openid 与 session_key）
const session = async code => {
  if (!configured()) throw new SE(400, '小程序服务未配置，请联系管理员');
  const { data } = await axios.get('https://api.weixin.qq.com/sns/jscode2session', {
    params: { appid: wxConf().appid, secret: wxConf().secret, js_code: code, grant_type: 'authorization_code' },
    timeout: 8000
  });
  if (!data.openid || !data.session_key) {
    throw new SE(400, data.errmsg || '微信登录失败，请重试');
  }
  const wxToken = jwt.sign({ openid: data.openid, sk: data.session_key }, config.jwtSecret, { expiresIn: '30d' });
  const link = await WxLink.findOne({ openid: data.openid });
  return { wxToken, bound: Boolean(link), anonymousId: link ? link.anonymousId : null };
};

// 绑定：wxToken + H5 绑定码 → openid ↔ OUTIE 身份
const bind = async (wxToken, code) => {
  let payload;
  try {
    payload = jwt.verify(wxToken, config.jwtSecret);
  } catch (e) {
    throw new SE(401, '小程序会话过期，请重新打开小程序');
  }
  const rec = takeBindCode(code);
  if (!rec) throw new SE(400, '绑定码错误或已过期。请在 OUTIE 网页重新生成。');
  await WxLink.updateOne(
    { openid: payload.openid },
    { openid: payload.openid, identityKey: rec.identityKey, anonymousId: rec.anonymousId },
    { upsert: true }
  );
  return { success: true, anonymousId: rec.anonymousId };
};

// WeRun 解密：AES-128-CBC（key=session_key, iv=回传iv）
const decryptWeRun = (sessionKey, encryptedData, iv) => {
  const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(sessionKey, 'base64'), Buffer.from(iv, 'base64'));
  decipher.setAutoPadding(true);
  const decoded = Buffer.concat([decipher.update(Buffer.from(encryptedData, 'base64')), decipher.final()]).toString('utf8');
  return JSON.parse(decoded);
};

// 步数入账：与页面内计步共用同一套经济（500步=1包、日上限15包、零头跨日），
// 以微信运动当日步数为准做差量入账（已计入的部分不重复发）
const creditWeRun = async (wxToken, encryptedData, iv) => {
  let payload;
  try {
    payload = jwt.verify(wxToken, config.jwtSecret);
  } catch (e) {
    throw new SE(401, '小程序会话过期，请重新打开小程序');
  }
  const link = await WxLink.findOne({ openid: payload.openid });
  if (!link) throw new SE(400, '先在 OUTIE 页面生成绑定码完成绑定');
  let run;
  try {
    run = decryptWeRun(payload.sk, encryptedData, iv);
  } catch (e) {
    throw new SE(400, '步数数据解密失败，请重新打开小程序再试');
  }
  const today = dayKeyOf();
  const todayEntry = (run.stepInfoList || []).find(item => {
    const t = new Date(item.timestamp * 1000 + 8 * 3600000);
    return t.toISOString().slice(0, 10) === today;
  });
  const realSteps = todayEntry ? todayEntry.step : 0;
  const pet = await OutiePet.findOne({ identityKey: link.identityKey }).sort({ createdAt: -1 });
  if (!pet) throw new SE(400, '还未领养宠物。请在 OUTIE 网页领养。');
  const sameDay = pet.stepsDayKey === today;
  const prevReal = sameDay ? (pet.wxCreditedDay || 0) : 0;
  const delta = Math.max(0, Math.min(realSteps - prevReal, 60000));
  if (delta <= 0) {
    return { feedTokens: pet.feedTokens == null ? 3 : pet.feedTokens, stepsToday: sameDay ? (pet.stepsDay || 0) : 0, credited: 0 };
  }
  const carryIn = sameDay ? (pet.stepsCarry || 0) : (pet.stepsCarry || 0);
  const earnedToday = pet.tokensEarnedKey === today ? (pet.tokensEarnedDay || 0) : 0;
  const carry = Math.min(carryIn + delta, 30000);
  const earnLeft = Math.max(0, 15 - earnedToday);
  const award = Math.min(Math.floor(carry / 500), earnLeft);
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id },
    { $set: { stepsDayKey: today, stepsCarry: carry - award * 500, wxCreditedDay: prevReal + delta, wxCreditedKey: today, tokensEarnedKey: today, tokensEarnedDay: earnedToday + award }, $inc: { stepsDay: delta, feedTokens: award } },
    { new: true }
  );
  return {
    feedTokens: updated.feedTokens == null ? 3 : updated.feedTokens,
    stepsToday: updated.stepsDay || 0,
    credited: delta,
    tokensAwarded: award,
    realSteps
  };
};

module.exports = { configured, genBindCode, takeBindCode, session, bind, creditWeRun };
