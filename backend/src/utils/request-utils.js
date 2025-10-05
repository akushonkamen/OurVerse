const crypto = require('crypto');

const getClientIp = req => req.headers['x-forwarded-for']?.split(',')[0]?.trim()
  || req.headers['x-real-ip']
  || req.connection?.remoteAddress
  || req.socket?.remoteAddress
  || req.ip
  || '';

const getDeviceFingerprint = req => {
  const rawDeviceId = (req.body?.deviceId || req.headers['x-device-id'] || '').toString().trim();
  const userAgent = req.headers['user-agent'] || '';

  if (rawDeviceId) {
    return { deviceId: rawDeviceId, source: 'client', userAgent };
  }

  const fallback = crypto.createHash('sha256')
    .update(`${getClientIp(req)}|${userAgent}`)
    .digest('hex');

  return { deviceId: fallback, source: 'fingerprint', userAgent };
};

module.exports = {
  getClientIp,
  getDeviceFingerprint
};
