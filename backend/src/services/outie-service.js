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

// 心情衰减：每小时 10 点（满值约 10 小时见底）——一天总衰减 240，每次喂 +25，恰好一天 10 包
const MOOD_DECAY_PER_HOUR = 10;
const MOOD_FLOOR = 10;
const deriveMood = pet => {
  if (!pet.lastFedAt) return 60;
  const hours = (Date.now() - new Date(pet.lastFedAt).getTime()) / 3600000;
  return Math.max(MOOD_FLOOR, Math.min(100, Math.round(100 - hours * MOOD_DECAY_PER_HOUR)));
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

// 上报本机计步：按日累计、按赚币上限发放（carry 攒零头，可跨日）
const syncStepsForIdentity = async (req, stepsInput) => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (!pet) throw new ServiceError(400, '先领养一只宠物，步数才有用处');
  let steps = Math.floor(Number(stepsInput));
  if (!Number.isFinite(steps) || steps <= 0) throw new ServiceError(400, '步数不对');
  steps = Math.min(steps, 2000);
  const today = dayKeyOf();
  const sameDay = pet.stepsDayKey === today;
  const earnedKeyToday = pet.tokensEarnedKey === today ? (pet.tokensEarnedDay || 0) : 0;
  const carry = (sameDay ? (pet.stepsCarry || 0) : 0) + steps;
  const earnLeft = Math.max(0, TOKENS_DAILY_CAP - earnedKeyToday);
  const award = Math.min(Math.floor(carry / STEPS_PER_TOKEN), earnLeft);
  const tokens = effectiveTokens(pet) + award;
  const carryLeft = carry - award * STEPS_PER_TOKEN;
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id },
    { $set: { stepsDayKey: today, stepsCarry: carryLeft, feedTokens: tokens, tokensEarnedKey: today, tokensEarnedDay: earnedKeyToday + award }, $inc: { stepsDay: steps } },
    { new: true }
  );
  return {
    feedTokens: effectiveTokens(updated),
    stepsToday: updated.stepsDay || 0,
    tokensAwarded: award,
    earnCapped: earnedKeyToday + award >= TOKENS_DAILY_CAP
  };
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
    throw new ServiceError(400, '饲料不够了：带着手机出门走走，50 步换 1 包');
  }
  const firstToday = pet.lastFeedDay !== today;
  const yesterday = dayKeyOf(new Date(Date.now() - 86400000));
  const streakNext = firstToday ? (pet.lastFeedDay === yesterday ? (pet.feedStreak || 0) + 1 : 1) : (pet.feedStreak || 0);
  const updated = await OutiePet.findOneAndUpdate(
    { _id: pet._id, $or: [{ feedTokens: { $gt: 0 } }, { feedTokens: null }] },
    { $inc: { feedTokens: -1, feedTotal: 1 }, $set: { lastFeedDay: today, lastFedAt: new Date(), feedStreak: streakNext } },
    { new: true }
  );
  if (!updated) throw new ServiceError(400, '饲料不够了：带着手机出门走走，50 步换 1 包');
  const event = await findActiveEvent();
  return { pet: serializePet(updated, event), alreadyFed: !firstToday, firstToday };
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

  const newPet = await OutiePet.create({
    identityKey,
    name: trimmedName,
    rewards: {},
    evolvedEvents: [],
    equipped: 'base'
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
    const radius = spot.radiusMeters || DEFAULT_SPOT_RADIUS_METERS;
    const distance = calculateDistance(viewerLat, viewerLng, spot.lat, spot.lng);
    if (distance > radius) {
      throw new ServiceError(400, `距离 ${spot.name} ${Math.round(distance)} 米，需靠近 ${radius} 米内才能打卡`, {
        distanceMeters: Math.round(distance)
      });
    }
  } else if (!config.outie.devSkipGeo) {
    throw new ServiceError(400, '缺少定位坐标，请允许定位后重试');
  }

  const otherEvents = { ...(pet.rewards || {}) };
  delete otherEvents[event.key];
  const perEvent = { ...eventRewardsOf(pet, event.key) };
  if (perEvent[spotKey]) {
    return {
      success: true,
      alreadyOwned: true,
      newlyEvolved: false,
      reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
      pet: serializePet(pet, event)
    };
  }

  perEvent[spotKey] = new Date();
  pet.rewards = { ...otherEvents, [event.key]: perEvent };

  const collected = Object.keys(perEvent).length;
  const totalSpots = (event.spots || []).length || LOOK_IDS.length;
  let newlyEvolved = false;
  if (collected >= totalSpots && !pet.evolvedEvents.includes(event.key)) {
    pet.evolvedEvents.push(event.key);
    newlyEvolved = true;
  }

  // 打卡接入养成经济：每站首打卡 +3 包，集齐活动再 +5 包，并把心情拉回不低于 85
  const tokenBonus = newlyEvolved ? 8 : 3;
  pet.feedTokens = (pet.feedTokens == null ? 3 : pet.feedTokens) + tokenBonus;
  const minFresh = Date.now() - 1.5 * 3600000;
  if (!pet.lastFedAt || new Date(pet.lastFedAt).getTime() < minFresh) {
    pet.lastFedAt = new Date(minFresh);
  }

  await pet.save();

  return {
    success: true,
    alreadyOwned: false,
    newlyEvolved,
    tokenBonus,
    reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
    pet: serializePet(pet, event)
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
    spots
  });
  return { success: true, event: serializeEvent(event) };
};

const listMyEvents = async req => {
  const identityKey = requireIdentity(req);
  const events = await OutieEvent.find({ organizerKey: identityKey }).sort({ createdAt: -1 }).limit(50);
  return { events: events.map(serializeEvent) };
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
  return {
    event: serializeEvent(event),
    center,
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
