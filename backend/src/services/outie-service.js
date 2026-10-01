const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const OutieEvent = require('../models/outie-event');
const OutiePet = require('../models/outie-pet');
const Photo = require('../models/photo');
const { calculateDistance } = require('../utils/geo-utils');
const config = require('../config/env');

const DEFAULT_SPOT_RADIUS_METERS = 200;
const LOOK_IDS = ['music', 'art', 'market'];
const STATIC_MAP_MIN_ZOOM = 10;
const STATIC_MAP_MAX_ZOOM = 19;
const STATIC_MAP_MAX_SIZE = 300;

class ServiceError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

const resolveIdentityKey = req => {
  if (req.userId) {
    return `u:${req.userId}`;
  }
  if (req.anonymousId) {
    return `a:${req.anonymousId}`;
  }
  return null;
};

const requireIdentity = req => {
  const identityKey = resolveIdentityKey(req);
  if (!identityKey) {
    throw new ServiceError(401, '请先登录或提供匿名标识');
  }
  return identityKey;
};

const findActiveEvent = () => OutieEvent.findOne({ active: true }).sort({ createdAt: -1 });

const findLatestPet = identityKey => OutiePet.findOne({ identityKey }).sort({ createdAt: -1 });

// 旧版数据结构（扁平 rewards：spotKey -> Date，加 evolved 布尔 + eventKey）惰性迁移到按活动分组
const isNestedEventRewards = v => (v instanceof Map) || (v && typeof v === 'object' && !(v instanceof Date));
const normalizeLegacyPet = pet => {
  const entries = Object.entries(pet.rewards || {});
  const legacyIsFlat = entries.some(([, v]) => !isNestedEventRewards(v));
  if (legacyIsFlat || (pet.evolved && pet.eventKey && !pet.evolvedEvents.includes(pet.eventKey))) {
    const eventKey = pet.eventKey || 'legacy';
    const flat = {};
    for (const [k, v] of entries) {
      if (!isNestedEventRewards(v)) flat[k] = v;
    }
    pet.rewards = { [eventKey]: flat };
    if (pet.evolved && pet.eventKey && !pet.evolvedEvents.includes(pet.eventKey)) {
      pet.evolvedEvents.push(pet.eventKey);
    }
    pet.markModified('rewards');
    pet.markModified('evolvedEvents');
    return pet.save();
  }
  return Promise.resolve(pet);
};

// 登录后若账号名下没有宠物，把当前匿名身份的宠物过户到账号，进度无缝衔接
// 注意：带 Bearer token 时中间件会把 req.anonymousId 置空，这里直接读原始请求头
const maybeMigrateAnonymousPet = async req => {
  if (!req.userId) return;
  const headerAnonId = (req.headers && req.headers['x-anonymous-id']) || '';
  if (!headerAnonId) return;
  const userKey = `u:${req.userId}`;
  const anonKey = `a:${headerAnonId}`;
  if (userKey === anonKey) return;
  const existingUserPet = await findLatestPet(userKey);
  if (existingUserPet) return;
  const anonPet = await findLatestPet(anonKey);
  if (!anonPet) return;
  anonPet.identityKey = userKey;
  await anonPet.save();
};

const serializeSpot = spot => ({
  key: spot.key,
  name: spot.name,
  zone: spot.zone || '',
  rewardName: spot.rewardName || '',
  lookId: spot.lookId || '',
  look: spot.look ? {
    name: spot.look.name || '',
    shape: spot.look.shape || 'blob',
    body: spot.look.body || '#a3463c',
    accent: spot.look.accent || '#41597e',
    pattern: spot.look.pattern || 'solid',
    accessory: spot.look.accessory || 'none'
  } : null,
  arrivalNote: spot.arrivalNote || '',
  amapPoiId: spot.amapPoiId || '',
  address: spot.address || '',
  lng: spot.lng,
  lat: spot.lat,
  radiusMeters: spot.radiusMeters || DEFAULT_SPOT_RADIUS_METERS
});

const serializeEvent = event => ({
  key: event.key,
  name: event.name,
  subtitle: event.subtitle || '',
  active: event.active,
  coverUrl: event.coverUrl || '',
  organizer: Boolean(event.organizerKey),
  spots: (event.spots || []).map(serializeSpot)
});

const collectedSpotKeys = pet => {
  const keys = new Set();
  for (const perEvent of Object.values(pet.rewards || {})) {
    for (const spotKey of Object.keys(perEvent || {})) keys.add(spotKey);
  }
  return keys;
};

const eventRewardsOf = (pet, eventKey) => (pet.rewards && pet.rewards[eventKey]) || {};

// 心情衰减分时制（旅行青蛙模型）：夜间宠物睡觉不衰减，白天匀速掉
// 推演：22:00 喂满 100 → 晨 8:30 约 84（不进饥饿态）→ 17:00 约 35 触发「饿了」→ 晚间二次喂食，日耗 2 包
const MOOD_FLOOR = 10;
const deriveMood = pet => {
  if (!pet.lastFedAt) return 60;
  let minutes = (Date.now() - new Date(pet.lastFedAt).getTime()) / 60000;
  let decayed = 0;
  // 逐时段累计衰减（东八区）：0-7 点 0/时，7-10 点 6/时，其余 8/时
  let cursor = new Date(pet.lastFedAt).getTime();
  const SEGMENTS = [[0, 7, 0], [7, 10, 6], [10, 24, 8]];
  while (minutes > 0) {
    const local = new Date(cursor + 8 * 3600000);
    const hour = local.getUTCHours() + local.getUTCMinutes() / 60;
    const seg = SEGMENTS.find(([a, b]) => hour >= a && hour < b) || SEGMENTS[2];
    const hourEnd = cursor + ((seg[1] - hour) * 3600000);
    const spanMin = Math.min(minutes, (hourEnd - cursor) / 60000);
    decayed += (spanMin / 60) * seg[2];
    cursor += spanMin * 60000;
    minutes -= spanMin;
    if (decayed >= 90) break;
  }
  return Math.max(MOOD_FLOOR, Math.min(100, Math.round(100 - decayed)));
};
// 东八区日期串，喂食以自然日为界
const dayKeyOf = (d = new Date()) => {
  const t = new Date(d.getTime() + 8 * 3600000);
  return t.toISOString().slice(0, 10);
};

const serializePet = (pet, event) => {
  const eventKey = event ? event.key : null;
  const rewards = eventKey ? eventRewardsOf(pet, eventKey) : {};
  const evolved = eventKey ? pet.evolvedEvents.includes(eventKey) : false;
  return {
    id: String(pet._id),
    identityKey: pet.identityKey,
    name: pet.name,
    eventKey,
    rewards,
    evolved,
    equipped: pet.equipped || 'base',
    mood: deriveMood(pet),
    fedToday: pet.lastFeedDay === dayKeyOf(),
    feedStreak: pet.feedStreak || 0,
    feedTotal: pet.feedTotal || 0,
    feedTokens: effectiveTokens(pet),
    stepsToday: pet.stepsDayKey === dayKeyOf() ? (pet.stepsDay || 0) : 0,
    stepsCarry: pet.stepsDayKey === dayKeyOf() ? (pet.stepsCarry || 0) : 0,
    tokensEarnedToday: pet.tokensEarnedKey === dayKeyOf() ? (pet.tokensEarnedDay || 0) : 0,
    createdAt: pet.createdAt
  };
};

// 步数经济：每 500 步兑 1 包饲料；每天最多赚 15 包（当天赚满后步数攒着次日再兑）
const STEPS_PER_TOKEN = 500;
const TOKENS_DAILY_CAP = 15;
const effectiveTokens = pet => (pet.feedTokens == null ? 3 : pet.feedTokens);

// 上报本机计步：$inc 原子发放（防与喂食并发时的铸币竞态）；速率闸与日赚上限防刷；零头跨日保留
const syncStepsForIdentity = async (req, stepsInput) => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (!pet) throw new ServiceError(400, '先领养一只宠物，步数才有用处');
  let steps = Math.floor(Number(stepsInput));
  if (!Number.isFinite(steps) || steps <= 0) throw new ServiceError(400, '步数不对');
  steps = Math.min(steps, 600);
  // 速率闸：步行生理上限约 150 步/分，超速部分按 150 步/分折算
  const now = Date.now();
  const lastAt = pet.lastStepSyncAt ? new Date(pet.lastStepSyncAt).getTime() : 0;
  const gapMin = lastAt ? Math.min(Math.max((now - lastAt) / 60000, 0.5), 1440) : 1440;
  if (now - lastAt < 15000) throw new ServiceError(429, '步数同步太频繁，稍等一下');
  const maxByRate = Math.ceil(gapMin * 150);
  const credited = Math.min(steps, maxByRate);

  const today = dayKeyOf();
  const sameDay = pet.stepsDayKey === today;
  const carryIn = sameDay ? (pet.stepsCarry || 0) : (pet.stepsCarry || 0); // 零头跨日保留（上限 2000）
  const earnedKeyToday = pet.tokensEarnedKey === today ? (pet.tokensEarnedDay || 0) : 0;
  const carry = Math.min(carryIn + credited, 2000);
  const earnLeft = Math.max(0, TOKENS_DAILY_CAP - earnedKeyToday);
  const award = Math.min(Math.floor(carry / STEPS_PER_TOKEN), earnLeft);
  const carryLeft = carry - award * STEPS_PER_TOKEN;
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id },
    { $set: { stepsDayKey: today, stepsCarry: carryLeft, tokensEarnedKey: today, tokensEarnedDay: earnedKeyToday + award, lastStepSyncAt: new Date(now) }, $inc: { stepsDay: credited, feedTokens: award } },
    { new: true }
  );
  return {
    feedTokens: effectiveTokens(updated),
    stepsToday: updated.stepsDay || 0,
    tokensAwarded: award,
    earnCapped: earnedKeyToday + award >= TOKENS_DAILY_CAP
  };
};

// 我的凭证：未核销列表（刷新后码不丢）
const myVouchers = async req => {
  const identityKey = requireIdentity(req);
  const Voucher = require('../models/voucher');
  const list = await Voucher.find({ identityKey, redeemedAt: null }).sort({ createdAt: -1 }).limit(20);
  const events = await OutieEvent.find({ key: { $in: list.map(v => v.eventKey) } }, { key: 1, name: 1 });
  const nameOf = new Map(events.map(e => [e.key, e.name]));
  return {
    vouchers: list.map(v => ({
      code: v.code,
      eventKey: v.eventKey,
      eventName: nameOf.get(v.eventKey) || v.eventKey,
      createdAt: v.createdAt
    }))
  };
};

// 商家核销：活动发布者按码核销
const redeemVoucher = async req => {
  const identityKey = requireIdentity(req);
  const code = String((req.body || {}).code || '').trim().toUpperCase();
  if (!/^[A-F0-9]{6}$/.test(code)) throw new ServiceError(400, '核销码格式不对');
  const Voucher = require('../models/voucher');
  const v = await Voucher.findOne({ code });
  if (!v) throw new ServiceError(404, '核销码不存在');
  const event = await OutieEvent.findOne({ key: v.eventKey });
  if (!event || event.organizerKey !== identityKey) throw new ServiceError(403, '只有发布者本人能核销这场活动的凭证');
  if (v.redeemedAt) throw new ServiceError(400, `该码已核销（${v.petName || '游客'}）`);
  v.redeemedAt = new Date();
  await v.save();
  return { success: true, code: v.code, petName: v.petName, redeemedAt: v.redeemedAt };
};

// 评论通知（拉取式）：我照片上别人留的新评论数（since 由前端 localStorage 维护）
const myCommentActivity = async req => {
  const since = new Date(Number(req.query.since) || (Date.now() - 7 * 86400000));
  const mine = req.userId
    ? { userId: req.userId }
    : { anonymousId: req.anonymousId || '' };
  const photos = await Photo.find({ ...mine, comments: { $ne: [] } }, { caption: 1, comments: 1 }).sort({ createdAt: -1 }).limit(50);
  let unread = 0;
  let latest = null;
  for (const ph of photos) {
    for (const c of ph.comments || []) {
      const at = new Date(c.createdAt).getTime();
      if (at <= since.getTime()) continue;
      const commenterKey = c.userId ? `u:${c.userId}` : (c.anonymousId ? `a:${c.anonymousId}` : '');
      const myKey = req.userId ? `u:${req.userId}` : `a:${req.anonymousId || ''}`;
      if (commenterKey === myKey) continue;
      unread += 1;
      if (!latest || at > latest.at) {
        latest = { at, photoId: String(ph._id), caption: String(ph.caption || '').slice(0, 30), text: String(c.text || '').slice(0, 40) };
      }
    }
  }
  return { unread, latest };
};

// 摸头：每日前 5 次、每次心情 +1（把 lastFedAt 提前 6 分钟=抵消 1 点衰减），服务端持久
const touchPetForIdentity = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (!pet) throw new ServiceError(400, '先领养一只宠物');
  const today = dayKeyOf();
  const n = pet.pettedDay === today ? (pet.pettedN || 0) : 0;
  if (n >= 5) return { mood: deriveMood(pet), capped: true };
  // 饲料 sink：前 3 次免费，第 4-5 次各耗 1 包（没包就只给前 3 次）
  const cost = n >= 3 ? 1 : 0;
  const startTokens = effectiveTokens(pet);
  if (cost && startTokens < 1) return { mood: deriveMood(pet), capped: true, needToken: true };
  const base = pet.lastFedAt ? new Date(pet.lastFedAt).getTime() : null;
  const legacyNull = pet.feedTokens == null;
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id },
    { $set: { pettedDay: today, pettedN: n + 1, ...(base ? { lastFedAt: new Date(base - 6 * 60000) } : {}), ...(legacyNull ? { feedTokens: startTokens - cost } : {}) }, ...(cost && !legacyNull ? { $inc: { feedTokens: -1 } } : {}) },
    { new: true }
  );
  if (!updated) return { mood: deriveMood(pet), capped: true, needToken: cost > 0 };
  return { mood: deriveMood(updated), capped: false, spent: cost };
};

// 喂食：消耗 1 包饲料（心情 +25），当天首次喂计连击；饲料不足明确拒绝
const feedPetForIdentity = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (!pet) throw new ServiceError(400, '先领养一只宠物，才能喂它');
  const today = dayKeyOf();
  const startingTokens = effectiveTokens(pet);
  if (startingTokens < 1) {
    throw new ServiceError(400, '饲料不够了：开着 OUTIE 走路，500 步换 1 包');
  }
  const firstToday = pet.lastFeedDay !== today;
  const yesterday = dayKeyOf(new Date(Date.now() - 86400000));
  const streakNext = firstToday ? (pet.lastFeedDay === yesterday ? (pet.feedStreak || 0) + 1 : 1) : (pet.feedStreak || 0);
  // 连击里程碑实体化：3/7/14/30/60/100 天首次到达 +5 包（正向奖励，不只 toast）
  const MILESTONES = [3, 7, 14, 30, 60, 100];
  const milestoneHit = firstToday && MILESTONES.includes(streakNext) ? streakNext : 0;
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id, $or: [{ feedTokens: { $gt: 0 } }, { feedTokens: null }] },
    { $inc: { feedTokens: -1 + (milestoneHit ? 5 : 0), feedTotal: 1 }, $set: { lastFeedDay: today, lastFedAt: new Date(), feedStreak: streakNext } },
    { new: true }
  );
  if (!updated) throw new ServiceError(400, '饲料不够了：开着 OUTIE 走路，500 步换 1 包');
  const event = await findActiveEvent();
  return { pet: serializePet(updated, event), alreadyFed: !firstToday, firstToday, milestone: milestoneHit };
};

// 全部进行中活动：定位失败/附近为空时，用户仍能看到可去的地方
const listActiveEvents = async () => {
  const events = await OutieEvent.find({ active: true }).sort({ createdAt: -1 }).limit(20);
  return {
    events: events.map(e => {
      const s = serializeEvent(e);
      const pts = (s.spots || []).filter(sp => Number.isFinite(sp.lng) && Number.isFinite(sp.lat));
      const center = pts.length
        ? { lng: pts.reduce((a, sp) => a + sp.lng, 0) / pts.length, lat: pts.reduce((a, sp) => a + sp.lat, 0) / pts.length }
        : null;
      return {
        key: s.key,
        name: s.name,
        subtitle: s.subtitle || '',
        coverUrl: s.coverUrl || '',
        spotCount: pts.length,
        center
      };
    })
  };
};

const getCurrentEventData = async () => {
  const event = await findActiveEvent();
  return {
    event: event ? serializeEvent(event) : null,
    devSkipGeo: config.outie.devSkipGeo
  };
};

// 领养与活动解耦：任何时候都可以拥有宠物；活动只决定去哪儿收集
const upsertPetForIdentity = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);

  const event = await findActiveEvent();
  const pet = await findLatestPet(identityKey);
  if (pet) await normalizeLegacyPet(pet);

  const { name, equipped } = req.body || {};
  const trimmedName = typeof name === 'string' ? name.trim().slice(0, 12) : '';

  if (pet) {
    if (trimmedName) {
      pet.name = trimmedName;
    }
    if (typeof equipped === 'string') {
      const owned = ['base', ...collectedSpotKeys(pet), ...(pet.evolvedEvents.length ? ['evolved'] : [])];
      if (owned.includes(equipped)) {
        pet.equipped = equipped;
      }
    }
    await pet.save();
    return { success: true, created: false, pet: serializePet(pet, event), event: event ? serializeEvent(event) : null };
  }

  if (!trimmedName) {
    throw new ServiceError(400, '先起一个名字');
  }

  // 邀请归因：ref=邀请人的宠物 _id → 找到其 identityKey，邀请人宠物 +2 包（双向奖励）
  const invitedByRaw = typeof (req.body || {}).invitedBy === 'string' ? req.body.invitedBy.slice(0, 64) : '';
  let invitedBy = '';
  if (invitedByRaw) {
    const inviterPet = await OutiePet.findById(invitedByRaw).catch(() => null);
    if (inviterPet && inviterPet.identityKey !== identityKey) {
      invitedBy = inviterPet.identityKey;
      await OutiePet.updateOne({ _id: inviterPet._id }, { $inc: { feedTokens: 2 } });
    }
  }
  const newPet = await OutiePet.create({
    identityKey,
    name: trimmedName,
    rewards: {},
    evolvedEvents: [],
    equipped: 'base',
    feedTokens: invitedBy ? 5 : 3,
    invitedBy
  });

  return { success: true, created: true, pet: serializePet(newPet, event), event: event ? serializeEvent(event) : null };
};

// 收藏馆：跨活动汇总已收集的造型（含 look spec），让往期活动成果可展示可穿戴
const collectionOf = async pet => {
  const eventKeys = Object.keys(pet.rewards || {}).filter(key => Object.keys(pet.rewards[key] || {}).length);
  if (!eventKeys.length) return [];
  const events = await OutieEvent.find({ key: { $in: eventKeys } });
  const byKey = new Map(events.map(e => [e.key, e]));
  return eventKeys.map(key => {
    const e = byKey.get(key);
    const per = pet.rewards[key] || {};
    const spots = (e ? e.spots || [] : []).filter(sp => per[sp.key]).map(sp => ({
      key: sp.key,
      name: sp.name || '',
      rewardName: sp.rewardName || '',
      look: sp.look ? {
        name: sp.look.name || '', shape: sp.look.shape || 'blob', body: sp.look.body || '#a3463c',
        accent: sp.look.accent || '#41597e', pattern: sp.look.pattern || 'solid', accessory: sp.look.accessory || 'none'
      } : null,
      lookId: sp.lookId || '',
      at: per[sp.key] instanceof Date ? per[sp.key].toISOString() : String(per[sp.key] || '')
    }));
    return {
      eventKey: key,
      eventName: e ? e.name : key,
      active: e ? Boolean(e.active) : false,
      evolved: (pet.evolvedEvents || []).includes(key),
      spots
    };
  }).filter(entry => entry.spots.length);
};

const getPetState = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (pet) await normalizeLegacyPet(pet);
  if (!pet) {
    return { pet: null };
  }
  const event = await findActiveEvent();
  return { pet: serializePet(pet, event), collection: await collectionOf(pet) };
};

const checkinAtSpot = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);

  const requestedEventKey = typeof (req.body || {}).eventKey === 'string' ? req.body.eventKey.trim() : '';
  const event = requestedEventKey
    ? await OutieEvent.findOne({ key: requestedEventKey, active: true })
    : await findActiveEvent();
  if (!event) {
    throw new ServiceError(404, '当前没有进行中的活动');
  }

  const { spotKey, userLng, userLat } = req.body || {};
  if (!spotKey) {
    throw new ServiceError(400, '缺少 spotKey');
  }

  const spot = (event.spots || []).find(item => item.key === spotKey);
  if (!spot) {
    throw new ServiceError(400, '活动点位不存在');
  }

  const pet = await findLatestPet(identityKey);
  if (pet) await normalizeLegacyPet(pet);
  if (!pet) {
    throw new ServiceError(404, '请先领养宠物');
  }

  const viewerLng = Number(userLng);
  const viewerLat = Number(userLat);
  const hasCoords = Number.isFinite(viewerLng) && Number.isFinite(viewerLat);

  if (hasCoords) {
    // 围栏按上报精度放宽：GPS 城市峡谷误差不该惩罚到场的人（accuracy*1.5 与固定半径取大者）
    const claimedAcc = Math.max(0, Math.min(Number((req.body || {}).accuracy) || 0, 500));
    const radius = Math.max(spot.radiusMeters || DEFAULT_SPOT_RADIUS_METERS, claimedAcc * 1.5);
    const distance = calculateDistance(viewerLat, viewerLng, spot.lat, spot.lng);
    if (distance > radius) {
      throw new ServiceError(400, `距离 ${spot.name} ${Math.round(distance)} 米，需靠近 ${radius} 米内才能打卡`, {
        distanceMeters: Math.round(distance)
      });
    }
  } else if (!config.outie.devSkipGeo) {
    throw new ServiceError(400, '缺少定位坐标，请允许定位后重试');
  }

  // 原子首打卡：rewards 里该点位已存在则返回已拥有（并发双发只结算一次）
  const spotPath = `rewards.${event.key}.${spotKey}`;
  const isSelfPlay = event.organizerKey === identityKey;
  const tokenBonus = isSelfPlay ? 0 : 3;
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id, [spotPath]: { $exists: false } },
    { $set: { [spotPath]: new Date() }, $inc: { feedTokens: tokenBonus } },
    { new: true }
  );
  if (!updated) {
    return {
      success: true,
      alreadyOwned: true,
      newlyEvolved: false,
      reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
      pet: serializePet(pet, event)
    };
  }

  // 打卡即券：活动启用到店凭证时，真实首打卡签发 6 位核销码（每身份每活动上限 5 张，防刷）
  let voucherCode = null;
  if (event.voucherEnabled && !isSelfPlay) {
    const Voucher = require('../models/voucher');
    const mineCount = await Voucher.countDocuments({ eventKey: event.key, identityKey });
    if (mineCount < 5) {
      voucherCode = String(crypto.randomBytes(3).toString('hex')).toUpperCase();
      try {
        await Voucher.create({ code: voucherCode, eventKey: event.key, spotKey, identityKey, petName: pet.name || '' });
      } catch (e) {
        voucherCode = null; // 码冲突极小概率：放弃这张不阻塞打卡
      }
    }
  }

  const perEvent = eventRewardsOf(updated, event.key) || {};
  const collected = Object.keys(perEvent).length;
  const totalSpots = (event.spots || []).length || LOOK_IDS.length;
  let newlyEvolved = false;
  let petAfter = updated;
  if (collected >= totalSpots && !updated.evolvedEvents.includes(event.key)) {
    // 集齐：追加 +8 包与进化（低频路径，允许二次写）
    const evolved = await OutiePet.findOneAndUpdate(
      { _id: updated._id, evolvedEvents: { $ne: event.key } },
      { $inc: { feedTokens: isSelfPlay ? 0 : 5 }, $push: { evolvedEvents: event.key } },
      { new: true }
    );
    petAfter = evolved || updated;
    newlyEvolved = Boolean(evolved);
  }

  // 心情保底拉回不低于 85（lastFedAt 提前到 1.5 小时前）
  const minFresh = Date.now() - 1.5 * 3600000;
  if (!petAfter.lastFedAt || new Date(petAfter.lastFedAt).getTime() < minFresh) {
    petAfter = await OutiePet.findOneAndUpdate({ _id: petAfter._id }, { $set: { lastFedAt: new Date(minFresh) } }, { new: true }) || petAfter;
  }

  // 同场共鸣：此地累计到场的独立训练家数 + 最近几位的名字（数字变人脸）
  const spotVisitors = await OutiePet.countDocuments({ [spotPath]: { $exists: true } });
  let visitorNames = [];
  if (spotVisitors > 1) {
    const visitorPets = await OutiePet.find({ [spotPath]: { $exists: true } }, { name: 1 }).sort({ updatedAt: -1, createdAt: -1 }).limit(5);
    visitorNames = visitorPets.map(vp => vp.name || '神秘训练家').filter(n => n && n !== (petAfter.name || ''));
  }
  const petFinal = petAfter;

  const totalBonus = tokenBonus + (newlyEvolved ? 5 : 0);
  return {
    success: true,
    alreadyOwned: false,
    spotVisitors,
    visitorNames,
    voucher: voucherCode ? { code: voucherCode, eventName: event.name, spotName: spot.name } : null,
    newlyEvolved,
    tokenBonus,
    reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
    pet: serializePet(petFinal, event)
  };
};

const saveCompositeFile = async (identityKey, file) => {
  const ownerSegment = identityKey.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 64) || 'anonymous';
  const now = new Date();
  const yearSegment = String(now.getUTCFullYear());
  const monthSegment = String(now.getUTCMonth() + 1).padStart(2, '0');

  const uploadsDirPosix = (config.uploadsDir || 'uploads').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const relativeDir = path.posix.join(uploadsDirPosix, 'outie', ownerSegment, yearSegment, monthSegment);
  const absoluteDir = path.resolve(__dirname, '..', '..', relativeDir);
  await fs.promises.mkdir(absoluteDir, { recursive: true });

  const extensionByMime = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif'
  };
  const extension = extensionByMime[file.mimetype] || 'jpg';
  const filename = `${crypto.randomBytes(16).toString('hex')}.${extension}`;
  await fs.promises.writeFile(path.join(absoluteDir, filename), file.buffer);

  return `/${path.posix.join(uploadsDirPosix, 'outie', ownerSegment, yearSegment, monthSegment, filename)}`;
};

const slug = () => crypto.randomBytes(5).toString('hex');

// 活动方：创建活动（含装扮插件规范）
const createEventForIdentity = async req => {
  const identityKey = requireIdentity(req);
  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name.trim().slice(0, 40) : '';
  if (!name) throw new ServiceError(400, '活动名称必填');
  // 防刷限额：单身份进行中活动 ≤3、每日新建 ≤2（防自建活动刷打卡奖励）
  const activeCount = await OutieEvent.countDocuments({ organizerKey: identityKey, active: true });
  const todayCount = await OutieEvent.countDocuments({ organizerKey: identityKey, createdAt: { $gte: new Date(Date.now() - 86400000) } });
  if (body.active !== false && activeCount >= 3) {
    throw new ServiceError(400, '进行中的活动最多 3 场，先下架一场再发布');
  }
  if (todayCount >= 2) {
    throw new ServiceError(400, '每天最多发布 2 场活动，明天再来');
  }

  const rawSpots = Array.isArray(body.spots) ? body.spots : [];
  const spots = rawSpots.slice(0, 10).map((sp, i) => {
    const lng = Number(sp.lng), lat = Number(sp.lat);
    if (!Number.isFinite(lng) || !Number.isFinite(lat)) {
      throw new ServiceError(400, `点位 ${i + 1} 缺少有效坐标`);
    }
    const look = sp.look && typeof sp.look === 'object' ? {
      name: String(sp.look.name || sp.rewardName || '').slice(0, 20),
      shape: ['blob', 'cat', 'bear', 'bunny'].includes(sp.look.shape) ? sp.look.shape : 'blob',
      body: /^#[0-9a-fA-F]{6}$/.test(String(sp.look.body)) ? sp.look.body : '#a3463c',
      accent: /^#[0-9a-fA-F]{6}$/.test(String(sp.look.accent)) ? sp.look.accent : '#41597e',
      pattern: ['solid', 'spots', 'stripes'].includes(sp.look.pattern) ? sp.look.pattern : 'solid',
      accessory: ['none', 'headphones', 'glasses', 'bag', 'crown', 'bow', 'scarf', 'cap', 'flower', 'bell'].includes(sp.look.accessory) ? sp.look.accessory : 'none'
    } : null;
    return {
      key: (typeof sp.key === 'string' && /^[a-z0-9_-]{1,20}$/i.test(sp.key)) ? sp.key : `s${i + 1}-${slug()}`,
      name: String(sp.name || `点位 ${i + 1}`).slice(0, 20),
      zone: String(sp.zone || '').slice(0, 12),
      rewardName: String(sp.rewardName || '').slice(0, 20),
      look,
      arrivalNote: String(sp.arrivalNote || '').slice(0, 40),
      address: String(sp.address || '').slice(0, 60),
      lng, lat,
      radiusMeters: Number(sp.radiusMeters) > 0 ? Math.min(Number(sp.radiusMeters), 1000) : DEFAULT_SPOT_RADIUS_METERS
    };
  });
  if (!spots.length) throw new ServiceError(400, '至少需要一个活动点位');

  const event = await OutieEvent.create({
    key: 'evt-' + slug(),
    name,
    subtitle: String(body.subtitle || '').slice(0, 40),
    active: body.active === true,
    organizerKey: identityKey,
    voucherEnabled: Boolean(body.voucherEnabled),
    spots
  });
  return { success: true, event: serializeEvent(event) };
};

// 商家数据面板：每个自有活动的客流证据（独立打卡用户/打卡次数/现场照片数）
const myEventStats = async identityKey => {
  const events = await OutieEvent.find({ organizerKey: identityKey }).sort({ createdAt: -1 }).limit(50);
  if (!events.length) return [];
  const stats = await Promise.all(events.map(async event => {
    const rewardsPath = `rewards.${event.key}`;
    // 独立打卡用户：rewards 里有这个活动分组的宠物数
    const visitors = await OutiePet.countDocuments({ [rewardsPath]: { $exists: true, $ne: {} } });
    // 打卡次数：这些宠物在该活动下的点位条目总和（小数据量直接算）
    let checkins = 0;
    if (visitors) {
      const pets = await OutiePet.find({ [rewardsPath]: { $exists: true, $ne: {} } }, { [`rewards.${event.key}`]: 1 });
      for (const p of pets) {
        const per = eventRewardsOf(p, event.key) || {};
        checkins += Object.keys(per).length;
      }
    }
    const photos = await Photo.countDocuments({ eventKey: event.key, isPromo: { $ne: true } });
    const Voucher = require('../models/voucher');
    const vouchersRedeemed = await Voucher.countDocuments({ eventKey: event.key, redeemedAt: { $ne: null } });
    const spots = (event.spots || []).length;
    return {
      key: event.key,
      name: event.name,
      active: Boolean(event.active),
      spotCount: spots,
      visitors,
      checkins,
      photos,
      vouchersRedeemed,
      voucherEnabled: Boolean(event.voucherEnabled),
      completed: visitors ? await OutiePet.countDocuments({ [rewardsPath]: { $exists: true }, $expr: { $gte: [{ $size: { $objectToArray: `$${rewardsPath}` } }, spots] } }) : 0
    };
  }));
  return stats;
};

const listMyEvents = async req => {
  const identityKey = requireIdentity(req);
  const events = await OutieEvent.find({ organizerKey: identityKey }).sort({ createdAt: -1 }).limit(50);
  return { events: events.map(serializeEvent), stats: await myEventStats(identityKey) };
};

const eventCenter = event => {
  const spots = (event.spots || []).filter(sp => Number.isFinite(sp.lng) && Number.isFinite(sp.lat));
  if (!spots.length) return null;
  return {
    lng: spots.reduce((a, sp) => a + sp.lng, 0) / spots.length,
    lat: spots.reduce((a, sp) => a + sp.lat, 0) / spots.length
  };
};

const nearbyEvents = async (lat, lng, radiusMeters) => {
  const events = await OutieEvent.find({ active: true }).sort({ createdAt: -1 }).limit(100);
  const withDistance = [];
  for (const event of events) {
    const center = eventCenter(event);
    if (!center) continue;
    const distance = calculateDistance(lat, lng, center.lat, center.lng);
    if (distance > radiusMeters) continue;
    withDistance.push({
      ...serializeEvent(event),
      center,
      distanceMeters: Math.round(distance)
    });
  }
  withDistance.sort((a, b) => a.distanceMeters - b.distanceMeters);
  return { events: withDistance };
};

const getEventByKey = async key => {
  const event = await OutieEvent.findOne({ key: String(key || '').slice(0, 60) });
  if (!event) throw new ServiceError(404, '活动不存在');
  const center = eventCenter(event);
  const promos = await Photo.find({ eventKey: event.key, isPromo: true }).sort({ createdAt: -1 }).limit(12);
  // 每个点位的到场训练家名字（社交证据常驻化：谁来过可回看）
  const Voucher = require('../models/voucher');
  const spotNames = await Promise.all((event.spots || []).map(async sp => {
    const path = `rewards.${event.key}.${sp.key}`;
    const pets = await OutiePet.find({ [path]: { $exists: true } }, { name: 1 }).sort({ [path]: -1 }).limit(6);
    const visitors = await OutiePet.countDocuments({ [path]: { $exists: true } });
    return { key: sp.key, visitors, names: pets.map(x => x.name || '神秘训练家') };
  }));
  return {
    event: serializeEvent(event),
    center,
    voucherEnabled: Boolean(event.voucherEnabled),
    spotVisitors: spotNames,
    promoPhotos: promos.map(ph => ({
      id: String(ph._id),
      url: ph.url,
      caption: ph.caption,
      createdAt: ph.createdAt
    }))
  };
};

const saveEventPromoPhoto = async req => {
  const identityKey = requireIdentity(req);
  const key = String((req.params || {}).key || '').slice(0, 60);
  const event = await OutieEvent.findOne({ key });
  if (!event) throw new ServiceError(404, '活动不存在');
  // 越权修复：只有发布者本人能传宣传照（旧活动无 organizerKey 也一律拒绝，防止抢占封面）
  if (!event.organizerKey || event.organizerKey !== identityKey) {
    throw new ServiceError(403, '只有发布者本人能上传这场活动的宣传照');
  }

  const file = req.file;
  if (req.fileValidationError) throw new ServiceError(400, req.fileValidationError);
  if (!file || !file.buffer || !file.buffer.length) throw new ServiceError(400, '缺少照片文件');

  const url = await saveCompositeFile(identityKey, file);
  const center = eventCenter(event) || { lng: 0, lat: 0 };
  const caption = String((req.body || {}).caption || '').trim().slice(0, 60) || `来自 ${event.name}`;
  const photo = await Photo.create({
    url,
    caption,
    lat: center.lat,
    lng: center.lng,
    location: { type: 'Point', coordinates: [center.lng, center.lat] },
    isAnonymous: !req.userId,
    anonymousId: req.userId ? null : (req.headers['x-anonymous-id'] || null),
    eventKey: event.key,
    isPromo: true
  });
  if (!event.coverUrl) {
    event.coverUrl = url;
    await event.save();
  }
  return { success: true, url, photoId: String(photo._id) };
};

const createCompositeRecord = async req => {
  const identityKey = requireIdentity(req);

  const file = req.file;
  if (req.fileValidationError) {
    throw new ServiceError(400, req.fileValidationError);
  }
  if (!file || !file.buffer || !file.buffer.length) {
    throw new ServiceError(400, '缺少照片文件');
  }

  const url = await saveCompositeFile(identityKey, file);
  return { success: true, url };
};

const TILE_SOURCES = [
  sub => `https://webrd0${sub}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8`
];

// 高德瓦片代理：浏览器直连高德会被 CORS 拦，由服务端代取
const fetchMapTile = async (z, x, y) => {
  const max = 1 << z;
  const sub = (x + y) % 4 + 1;
  const url = `https://webrd0${sub}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x=${x}&y=${y}&z=${z}`;
  const upstream = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!upstream.ok) {
    throw new ServiceError(502, '瓦片拉取失败');
  }
  return { buffer: Buffer.from(await upstream.arrayBuffer()), contentType: upstream.headers.get('content-type') || 'image/png' };
};

const getMapTile = async (z, x, y) => {
  const max = 1 << Math.min(Math.max(z, 10), 19);
  if (x < 0 || x >= max || y < 0 || y >= max) {
    throw new ServiceError(400, 'tile 参数无效');
  }
  const sub = (x + y) % 4 + 1;
  const url = `https://webrd0${sub}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x=${x}&y=${y}&z=${z}`;
  const upstream = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!upstream.ok) {
    throw new ServiceError(502, '瓦片拉取失败');
  }
  return { buffer: Buffer.from(await upstream.arrayBuffer()), contentType: upstream.headers.get('content-type') || 'image/png' };
};

const buildStaticMapUrl = query => {
  const key = config.amap.restApiKey;
  if (!key) {
    throw new ServiceError(503, '静态地图服务未配置');
  }

  const parts = String(query.location || '').split(',').map(value => Number(value));
  if (parts.length !== 2 || parts.some(value => !Number.isFinite(value))) {
    throw new ServiceError(400, 'location 参数无效，需为 lng,lat');
  }
  const [lng, lat] = parts;
  if (lng < -180 || lng > 180 || lat < -85 || lat > 85) {
    throw new ServiceError(400, 'location 参数无效，需为 lng,lat');
  }

  const zoom = Number.parseInt(query.zoom, 10);
  if (!Number.isFinite(zoom) || zoom < STATIC_MAP_MIN_ZOOM || zoom > STATIC_MAP_MAX_ZOOM) {
    throw new ServiceError(400, `zoom 需在 ${STATIC_MAP_MIN_ZOOM}-${STATIC_MAP_MAX_ZOOM} 之间`);
  }

  const match = /^(\d{1,3})\*(\d{1,3})$/.exec(String(query.size || ''));
  if (!match) {
    throw new ServiceError(400, `size 参数无效，需为 宽*高 且不超过 ${STATIC_MAP_MAX_SIZE}*${STATIC_MAP_MAX_SIZE}`);
  }
  const width = Number(match[1]);
  const height = Number(match[2]);
  if (!width || !height || width > STATIC_MAP_MAX_SIZE || height > STATIC_MAP_MAX_SIZE) {
    throw new ServiceError(400, `size 参数无效，需为 宽*高 且不超过 ${STATIC_MAP_MAX_SIZE}*${STATIC_MAP_MAX_SIZE}`);
  }

  const search = new URLSearchParams({
    key,
    location: `${lng},${lat}`,
    zoom: String(zoom),
    size: `${width}*${height}`,
    scale: '1'
  });
  return `https://restapi.amap.com/v3/staticmap?${search.toString()}`;
};

module.exports = {
  ServiceError,
  LOOK_IDS,
  getMapTile,
  createEventForIdentity,
  listMyEvents,
  nearbyEvents,
  listActiveEvents,
  feedPetForIdentity,
  touchPetForIdentity,
  myCommentActivity,
  myVouchers,
  redeemVoucher,
  syncStepsForIdentity,
  getEventByKey,
  saveEventPromoPhoto,
  resolveIdentityKey,
  serializeEvent,
  serializePet,
  getCurrentEventData,
  upsertPetForIdentity,
  getPetState,
  checkinAtSpot,
  createCompositeRecord,
  buildStaticMapUrl
};
