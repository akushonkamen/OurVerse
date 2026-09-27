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

const parseStaticMapLocation = raw => {
  const parts = String(raw || '').split(',').map(value => Number(value));
  if (parts.length !== 2 || parts.some(value => !Number.isFinite(value))) {
    return null;
  }
  const [lng, lat] = parts;
  if (lng < -180 || lng > 180 || lat < -85 || lat > 85) {
    return null;
  }
  return `${lng},${lat}`;
};

const parseStaticMapSize = raw => {
  const match = /^(\d{1,3})\*(\d{1,3})$/.exec(String(raw || ''));
  if (!match) {
    return null;
  }
  const width = Number(match[1]);
  const height = Number(match[2]);
  if (!width || !height || width > STATIC_MAP_MAX_SIZE || height > STATIC_MAP_MAX_SIZE) {
    return null;
  }
  return { width, height };
};

const staticMap = (req, res) => {
  const key = config.amap.restApiKey;
  if (!key) {
    return res.status(503).json({ error: '静态地图服务未配置' });
  }

  const location = parseStaticMapLocation(req.query.location);
  if (!location) {
    return res.status(400).json({ error: 'location 参数无效，需为 lng,lat' });
  }

  const zoom = Number.parseInt(req.query.zoom, 10);
  if (!Number.isFinite(zoom) || zoom < STATIC_MAP_MIN_ZOOM || zoom > STATIC_MAP_MAX_ZOOM) {
    return res.status(400).json({ error: `zoom 需在 ${STATIC_MAP_MIN_ZOOM}-${STATIC_MAP_MAX_ZOOM} 之间` });
  }

  const size = parseStaticMapSize(req.query.size);
  if (!size) {
    return res.status(400).json({ error: `size 参数无效，需为 宽*高 且不超过 ${STATIC_MAP_MAX_SIZE}*${STATIC_MAP_MAX_SIZE}` });
  }

  const query = new URLSearchParams({
    key,
    location,
    zoom: String(zoom),
    size: `${size.width}*${size.height}`,
    scale: '1'
  });
  return res.redirect(302, `https://restapi.amap.com/v3/staticmap?${query.toString()}`);
};

const amapConfig = (req, res) => {
  const jsKey = config.amap.webApiKey;
  if (!jsKey) {
    return res.status(503).json({ error: '地图服务未配置' });
  }
  res.json({ jsKey, securityCode: config.amap.securityCode || '' });
};

const serializeSpot = spot => ({
  key: spot.key,
  name: spot.name,
  zone: spot.zone || '',
  rewardName: spot.rewardName || '',
  lookId: spot.lookId,
  arrivalNote: spot.arrivalNote || '',
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

const serializePet = pet => ({
  id: String(pet._id),
  identityKey: pet.identityKey,
  name: pet.name,
  eventKey: pet.eventKey,
  rewards: Object.fromEntries(pet.rewards instanceof Map ? pet.rewards : new Map(Object.entries(pet.rewards || {}))),
  equipped: pet.equipped || 'base',
  evolved: Boolean(pet.evolved),
  createdAt: pet.createdAt
});

const resolveIdentityKey = req => {
  if (req.userId) {
    return `u:${req.userId}`;
  }
  if (req.anonymousId) {
    return `a:${req.anonymousId}`;
  }
  return null;
};

const findActiveEvent = () => OutieEvent.findOne({ active: true }).sort({ createdAt: -1 });

const findPet = (identityKey, eventKey) => OutiePet.findOne({ identityKey, eventKey });

const getCurrentEvent = async (req, res) => {
  try {
    const event = await findActiveEvent();
    if (!event) {
      return res.json({ event: null });
    }
    res.json({
      event: serializeEvent(event),
      devSkipGeo: config.outie.devSkipGeo
    });
  } catch (error) {
    console.error('Outie get current event error:', error);
    res.status(500).json({ error: '获取活动失败，请重试' });
  }
};

const upsertPet = async (req, res) => {
  try {
    const identityKey = resolveIdentityKey(req);
    if (!identityKey) {
      return res.status(401).json({ error: '请先登录或提供匿名标识' });
    }

    const event = await findActiveEvent();
    if (!event) {
      return res.status(404).json({ error: '当前没有进行中的活动' });
    }

    const { name, equipped } = req.body || {};
    const trimmedName = typeof name === 'string' ? name.trim().slice(0, 12) : '';
    const pet = await findPet(identityKey, event.key);

    if (pet) {
      if (trimmedName) {
        pet.name = trimmedName;
      }
      if (typeof equipped === 'string') {
        const allowedEquipped = ['base', ...LOOK_IDS.filter(look => pet.rewards.has(look))];
        if (pet.evolved) {
          allowedEquipped.push('evolved');
        }
        if (allowedEquipped.includes(equipped)) {
          pet.equipped = equipped;
        }
      }
      await pet.save();
      return res.json({ success: true, created: false, pet: serializePet(pet), event: serializeEvent(event) });
    }

    if (!trimmedName) {
      return res.status(400).json({ error: '先起一个名字' });
    }

    const newPet = await OutiePet.create({
      identityKey,
      name: trimmedName,
      eventKey: event.key,
      rewards: {},
      equipped: 'base',
      evolved: false
    });

    res.json({ success: true, created: true, pet: serializePet(newPet), event: serializeEvent(event) });
  } catch (error) {
    console.error('Outie create pet error:', error);
    res.status(500).json({ error: '领养失败，请重试' });
  }
};

const getMe = async (req, res) => {
  try {
    const identityKey = resolveIdentityKey(req);
    if (!identityKey) {
      return res.status(401).json({ error: '请先登录或提供匿名标识' });
    }

    const pet = await OutiePet.findOne({ identityKey }).sort({ createdAt: -1 });
    if (!pet) {
      return res.json({ pet: null });
    }

    res.json({ pet: serializePet(pet) });
  } catch (error) {
    console.error('Outie get me error:', error);
    res.status(500).json({ error: '获取宠物状态失败，请重试' });
  }
};

const checkin = async (req, res) => {
  try {
    const identityKey = resolveIdentityKey(req);
    if (!identityKey) {
      return res.status(401).json({ error: '请先登录或提供匿名标识' });
    }

    const event = await findActiveEvent();
    if (!event) {
      return res.status(404).json({ error: '当前没有进行中的活动' });
    }

    const { spotKey, userLng, userLat } = req.body || {};
    if (!spotKey) {
      return res.status(400).json({ error: '缺少 spotKey' });
    }

    const spot = (event.spots || []).find(item => item.key === spotKey);
    if (!spot) {
      return res.status(400).json({ error: '活动点位不存在' });
    }

    const pet = await findPet(identityKey, event.key);
    if (!pet) {
      return res.status(404).json({ error: '请先领养宠物' });
    }

    const viewerLng = Number(userLng);
    const viewerLat = Number(userLat);
    const hasCoords = Number.isFinite(viewerLng) && Number.isFinite(viewerLat);

    if (hasCoords) {
      const radius = spot.radiusMeters || DEFAULT_SPOT_RADIUS_METERS;
      const distance = calculateDistance(viewerLat, viewerLng, spot.lat, spot.lng);
      if (distance > radius) {
        return res.status(400).json({
          error: `距离 ${spot.name} ${Math.round(distance)} 米，需靠近 ${radius} 米内才能打卡`,
          distanceMeters: Math.round(distance)
        });
      }
    } else if (!config.outie.devSkipGeo) {
      return res.status(400).json({ error: '缺少定位坐标，请允许定位后重试' });
    }

    if (pet.rewards.has(spotKey)) {
      return res.json({
        success: true,
        alreadyOwned: true,
        newlyEvolved: false,
        reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
        pet: serializePet(pet)
      });
    }

    pet.rewards.set(spotKey, new Date());
    const rewardCount = LOOK_IDS.filter(look => pet.rewards.has(look)).length;
    let newlyEvolved = false;
    if (rewardCount >= LOOK_IDS.length && !pet.evolved) {
      pet.evolved = true;
      newlyEvolved = true;
    }
    if (!LOOK_IDS.includes(pet.equipped)) {
      pet.equipped = 'base';
    }

    await pet.save();

    res.json({
      success: true,
      alreadyOwned: false,
      newlyEvolved,
      reward: { spotKey, lookId: spot.lookId, rewardName: spot.rewardName || '' },
      pet: serializePet(pet)
    });
  } catch (error) {
    console.error('Outie checkin error:', error);
    res.status(500).json({ error: '打卡失败，请重试' });
  }
};

const createComposite = async (req, res) => {
  try {
    const identityKey = resolveIdentityKey(req);
    if (!identityKey) {
      return res.status(401).json({ error: '请先登录或提供匿名标识' });
    }

    const file = req.file;
    if (req.fileValidationError) {
      return res.status(400).json({ error: req.fileValidationError });
    }
    if (!file || !file.buffer || !file.buffer.length) {
      return res.status(400).json({ error: '缺少照片文件' });
    }

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

    res.json({
      success: true,
      url: `/${path.posix.join(uploadsDirPosix, 'outie', ownerSegment, yearSegment, monthSegment, filename)}`
    });
  } catch (error) {
    console.error('Outie create composite error:', error);
    res.status(500).json({ error: '合成照保存失败，请重试' });
  }
};

module.exports = {
  getCurrentEvent,
  upsertPet,
  getMe,
  checkin,
  createComposite,
  staticMap,
  amapConfig
};
