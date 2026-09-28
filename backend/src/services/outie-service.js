const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const OutieEvent = require('../models/outie-event');
const OutiePet = require('../models/outie-pet');
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
  lookId: spot.lookId,
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
    createdAt: pet.createdAt
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

const getPetState = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);
  const pet = await findLatestPet(identityKey);
  if (pet) await normalizeLegacyPet(pet);
  if (!pet) {
    return { pet: null };
  }
  const event = await findActiveEvent();
  return { pet: serializePet(pet, event) };
};

const checkinAtSpot = async req => {
  const identityKey = requireIdentity(req);
  await maybeMigrateAnonymousPet(req);

  const event = await findActiveEvent();
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
  let newlyEvolved = false;
  if (collected >= LOOK_IDS.length && !pet.evolvedEvents.includes(event.key)) {
    pet.evolvedEvents.push(event.key);
    newlyEvolved = true;
  }

  await pet.save();

  return {
    success: true,
    alreadyOwned: false,
    newlyEvolved,
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
