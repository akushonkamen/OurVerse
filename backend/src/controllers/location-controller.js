const config = require('../config/env');
const { toCleanString } = require('../utils/string-utils');
const { getClientIp } = require('../utils/request-utils');
const { lookupIp, deriveLocationFromIpData, reverseGeocode } = require('../services/amap-service');

const isPrivateIp = ip => ip.startsWith('10.')
  || ip.startsWith('192.168.')
  || (ip.startsWith('172.') && (() => {
    const segments = ip.split('.');
    const secondOctet = Number(segments[1]);
    return Number.isFinite(secondOctet) && secondOctet >= 16 && secondOctet <= 31;
  })())
  || ['127.0.0.1', '::1', ''].includes(ip);

const getIpLocation = async (req, res) => {
  try {
    if (!config.amap.restApiKey) {
      return res.status(500).json({
        error: '高德Web服务API密钥未配置',
        source: 'ip'
      });
    }

    const fallbackDisplayIp = getClientIp(req) || '';
    const ipOverride = toCleanString(req.query.ip || req.query.testIp);
    const candidateIp = fallbackDisplayIp.replace('::ffff:', '');
    const ipToQuery = ipOverride || (isPrivateIp(candidateIp) ? undefined : candidateIp);

    if (!ipToQuery && !ipOverride) {
      console.warn('IP定位请求来自私有网络，建议在开发环境通过 ?ip=xxx 指定测试IP');
    }

    const data = await lookupIp(ipToQuery);
    if (data.status !== '1' || data.infocode !== '10000') {
      console.error('高德IP定位失败:', data);
      return res.status(400).json({
        error: data.info || 'IP定位失败',
        source: 'ip',
        details: data
      });
    }

    const derived = await deriveLocationFromIpData(data);

    const responsePayload = {
      success: true,
      source: 'ip',
      ip: ipToQuery || candidateIp || '',
      location: {
        lat: derived.lat,
        lng: derived.lng,
        province: toCleanString(data.province),
        city: toCleanString(data.city),
        adcode: toCleanString(data.adcode),
        rectangle: toCleanString(data.rectangle),
        accuracyRadiusMeters: derived.accuracyRadiusMeters
      },
      metadata: {
        isp: toCleanString(data.isp),
        infoCode: data.infocode,
        requestIp: candidateIp,
        usedOverride: Boolean(ipOverride)
      }
    };

    if (!Number.isFinite(responsePayload.location.lat) || !Number.isFinite(responsePayload.location.lng)) {
      responsePayload.location.lat = null;
      responsePayload.location.lng = null;
    }

    res.json(responsePayload);
  } catch (error) {
    console.error('IP定位错误:', error.message);
    res.status(500).json({
      error: 'IP定位服务暂时不可用',
      source: 'ip',
      details: error.message
    });
  }
};

const getReverseGeocode = async (req, res) => {
  try {
    const { lat, lng } = req.query;

    if (!lat || !lng) {
      return res.status(400).json({ error: '缺少经纬度参数' });
    }

    const numericLat = Number(lat);
    const numericLng = Number(lng);

    if (!Number.isFinite(numericLat) || !Number.isFinite(numericLng)) {
      return res.status(400).json({ error: '经纬度格式不正确' });
    }

    const data = await reverseGeocode(numericLat, numericLng);

    if (data.status === '1' && data.regeocode) {
      const regeocode = data.regeocode;
      res.json({
        success: true,
        address: {
          formattedAddress: toCleanString(regeocode.formatted_address),
          country: toCleanString(regeocode.addressComponent?.country),
          province: toCleanString(regeocode.addressComponent?.province),
          city: toCleanString(regeocode.addressComponent?.city),
          district: toCleanString(regeocode.addressComponent?.district),
          township: toCleanString(regeocode.addressComponent?.township),
          street: toCleanString(regeocode.addressComponent?.streetNumber?.street),
          number: toCleanString(regeocode.addressComponent?.streetNumber?.number),
          adcode: toCleanString(regeocode.addressComponent?.adcode),
          citycode: toCleanString(regeocode.addressComponent?.citycode)
        },
        pois: regeocode.pois?.slice(0, 5) || [],
        roads: regeocode.roads?.slice(0, 3) || []
      });
    } else {
      console.error('逆地理编码失败:', data);
      res.status(400).json({
        success: false,
        error: data.info || '逆地理编码失败',
        details: data
      });
    }
  } catch (error) {
    console.error('逆地理编码请求处理错误:', error.message);
    res.status(500).json({
      success: false,
      error: '服务器内部错误',
      details: error.message
    });
  }
};

module.exports = {
  getIpLocation,
  getReverseGeocode
};
