const axios = require('axios');
const config = require('../config/env');
const { toCleanString } = require('../utils/string-utils');
const { calculateDistance, parseAmapRectangle } = require('../utils/geo-utils');

const getRestApiKey = () => {
  if (!config.amap.restApiKey) {
    throw new Error('高德Web服务API密钥未配置');
  }
  return config.amap.restApiKey;
};

const getReverseGeocodeKey = () => {
  const key = config.amap.restApiKey || config.amap.webApiKey;
  if (!key) {
    throw new Error('高德Web服务API密钥未配置');
  }
  return key;
};

const reverseGeocode = async (lat, lng, options = {}) => {
  const apiKey = getReverseGeocodeKey();

  const params = {
    key: apiKey,
    location: `${lng},${lat}`,
    extensions: options.extensions ?? 'all',
    radius: options.radius ?? 1000,
    roadlevel: options.roadlevel ?? 1
  };

  if (config.amap.securityCode) {
    params.sec_code = config.amap.securityCode;
  }

  const response = await axios.get('https://restapi.amap.com/v3/geocode/regeo', {
    params,
    timeout: options.timeout ?? 5000
  });

  return response.data;
};

const geocodeCity = async (city, province) => {
  const apiKey = getReverseGeocodeKey();

  const response = await axios.get('https://restapi.amap.com/v3/geocode/geo', {
    params: {
      key: apiKey,
      address: city,
      city: province || city
    },
    timeout: 5000
  });

  return response.data;
};

const lookupIp = async ip => {
  const apiKey = getRestApiKey();

  const params = { key: apiKey };
  if (ip) {
    params.ip = ip;
  }

  const response = await axios.get('https://restapi.amap.com/v3/ip', {
    params,
    timeout: 5000
  });

  return response.data;
};

const buildPhotoLocationInfo = async (lat, lng) => {
  let locationInfo = {
    country: '',
    province: '',
    city: '',
    district: '',
    township: '',
    street: '',
    number: '',
    address: `${lat.toFixed(6)}, ${lng.toFixed(6)}`,
    formattedAddress: `${lat.toFixed(6)}, ${lng.toFixed(6)}`,
    landmark: '',
    nearestPoi: ''
  };

  try {
    const data = await reverseGeocode(lat, lng);
    if (data.status === '1' && data.regeocode) {
      const regeocode = data.regeocode;
      const addr = regeocode.addressComponent || {};

      locationInfo = {
        country: toCleanString(addr.country),
        province: toCleanString(addr.province),
        city: toCleanString(addr.city),
        district: toCleanString(addr.district),
        township: toCleanString(addr.township),
        street: toCleanString(addr.streetNumber?.street),
        number: toCleanString(addr.streetNumber?.number),
        address: toCleanString(regeocode.formatted_address) || `${lat.toFixed(6)}, ${lng.toFixed(6)}`,
        formattedAddress: toCleanString(regeocode.formatted_address) || `${lat.toFixed(6)}, ${lng.toFixed(6)}`,
        landmark: '',
        nearestPoi: ''
      };

      if (Array.isArray(regeocode.pois) && regeocode.pois.length > 0) {
        const sortedPois = [...regeocode.pois].sort((a, b) => parseFloat(a.distance || 1000) - parseFloat(b.distance || 1000));
        const nearestPoi = sortedPois[0];
        const poiName = toCleanString(nearestPoi?.name);
        locationInfo.nearestPoi = poiName;
        locationInfo.landmark = poiName;
      }
    }
  } catch (error) {
    console.log('逆地理编码失败，使用坐标作为地址:', error.message);
  }

  return locationInfo;
};

const deriveLocationFromIpData = async data => {
  const rectangleInfo = parseAmapRectangle(data.rectangle);

  let derivedLat = rectangleInfo?.centerLat;
  let derivedLng = rectangleInfo?.centerLng;
  let radiusMeters;

  if (rectangleInfo) {
    radiusMeters = Math.round(
      calculateDistance(
        rectangleInfo.centerLat,
        rectangleInfo.centerLng,
        rectangleInfo.southwest.lat,
        rectangleInfo.southwest.lng
      ) || 0
    );
  }

  if ((!Number.isFinite(derivedLat) || !Number.isFinite(derivedLng)) && data.city) {
    try {
      const geoResult = await geocodeCity(data.city, data.province || data.city);
      if (geoResult.status === '1' && Array.isArray(geoResult.geocodes) && geoResult.geocodes[0]?.location) {
        const [geoLng, geoLat] = geoResult.geocodes[0].location.split(',').map(Number);
        if (Number.isFinite(geoLat) && Number.isFinite(geoLng)) {
          derivedLat = geoLat;
          derivedLng = geoLng;
        }
      }
    } catch (geoError) {
      console.warn('地理编码补偿失败:', geoError.message);
    }
  }

  return {
    lat: Number.isFinite(derivedLat) ? derivedLat : null,
    lng: Number.isFinite(derivedLng) ? derivedLng : null,
    accuracyRadiusMeters: radiusMeters || null
  };
};

module.exports = {
  reverseGeocode,
  geocodeCity,
  lookupIp,
  buildPhotoLocationInfo,
  deriveLocationFromIpData
};
