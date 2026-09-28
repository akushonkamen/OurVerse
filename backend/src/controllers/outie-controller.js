const outieService = require('../services/outie-service');
const config = require('../config/env');

const handleError = (res, error, fallbackMessage) => {
  if (error && error instanceof outieService.ServiceError) {
    return res.status(error.status).json({ error: error.message, ...error.extra });
  }
  console.error(fallbackMessage, error);
  return res.status(500).json({ error: fallbackMessage });
};

const getCurrentEvent = async (req, res) => {
  try {
    res.json(await outieService.getCurrentEventData());
  } catch (error) {
    handleError(res, error, '获取活动失败，请重试');
  }
};

const upsertPet = async (req, res) => {
  try {
    res.json(await outieService.upsertPetForIdentity(req));
  } catch (error) {
    handleError(res, error, '领养失败，请重试');
  }
};

const getMe = async (req, res) => {
  try {
    res.json(await outieService.getPetState(req));
  } catch (error) {
    handleError(res, error, '获取宠物状态失败，请重试');
  }
};

const checkin = async (req, res) => {
  try {
    res.json(await outieService.checkinAtSpot(req));
  } catch (error) {
    handleError(res, error, '打卡失败，请重试');
  }
};

const createComposite = async (req, res) => {
  try {
    res.json(await outieService.createCompositeRecord(req));
  } catch (error) {
    handleError(res, error, '合成照保存失败，请重试');
  }
};

const getMapTile = async (req, res) => {
  try {
    const z = Number.parseInt(req.params.z, 10);
    const x = Number.parseInt(req.params.x, 10);
    const y = Number.parseInt(req.params.y, 10);
    const { buffer, contentType } = await outieService.getMapTile(z, x, y);
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('Access-Control-Allow-Origin', '*');
    return res.send(buffer);
  } catch (error) {
    if (error && error instanceof outieService.ServiceError) {
      return res.status(error.status).json({ error: error.message });
    }
    console.warn('Outie map tile error:', error.message);
    return res.status(502).json({ error: '瓦片拉取失败' });
  }
};

const staticMap = async (req, res) => {
  let upstream;
  try {
    const url = outieService.buildStaticMapUrl(req.query);
    upstream = await fetch(url);
    if (!upstream.ok) {
      return res.status(502).json({ error: '静态地图拉取失败' });
    }
    res.set('Content-Type', upstream.headers.get('content-type') || 'image/png');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (error) {
    if (error && error instanceof outieService.ServiceError) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error('Outie static map error:', error);
    return res.status(500).json({ error: '静态地图拉取失败' });
  } finally {
    if (upstream && upstream.body) {
      upstream.body.cancel().catch(() => {});
    }
  }
};

const amapConfig = (req, res) => {
  const jsKey = config.amap.webApiKey;
  if (!jsKey) {
    return res.status(503).json({ error: '地图服务未配置' });
  }
  res.json({ jsKey, securityCode: config.amap.securityCode || '' });
};

module.exports = {
  getCurrentEvent,
  upsertPet,
  getMe,
  checkin,
  createComposite,
  staticMap,
  getMapTile,
  amapConfig
};
