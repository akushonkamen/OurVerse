const crypto = require('crypto');
const Photo = require('../models/photo');

const generateAnonymousId = () => crypto.randomUUID();

const getOrCreateAnonymousId = req => {
  const fromHeader = (req.headers['x-anonymous-id'] || '').toString().trim();
  if (fromHeader) return fromHeader;
  const fromBody = (req.body?.anonymousId || '').toString().trim();
  if (fromBody) return fromBody;
  return generateAnonymousId();
};

const assertAnonymousUploadQuota = async (anonymousId, limit) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);

  const count = await Photo.countDocuments({
    anonymousId,
    isAnonymous: true,
    createdAt: { $gte: today, $lt: tomorrow }
  });

  if (count >= limit) {
    const err = new Error(`每日匿名打卡上限为${limit}次`);
    err.code = 'QUOTA_EXCEEDED';
    throw err;
  }
};

module.exports = {
  generateAnonymousId,
  getOrCreateAnonymousId,
  assertAnonymousUploadQuota
};
