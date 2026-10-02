const Bar = require('../models/bar');
const User = require('../models/user');
const { calculateDistance } = require('../utils/geo-utils');

const MAX_CHECKIN_DISTANCE_METERS = 200;

const checkinAtBar = async (req, res) => {
  try {
    const { amapPoiId, name, address, lng, lat, userLng, userLat, note } = req.body || {};

    if (!amapPoiId || !name || !Number.isFinite(Number(lng)) || !Number.isFinite(Number(lat))) {
      return res.status(400).json({ error: '缺少酒吧定位信息' });
    }

    const barLng = Number(lng);
    const barLat = Number(lat);
    const viewerLng = Number(userLng);
    const viewerLat = Number(userLat);

    if (Number.isFinite(viewerLng) && Number.isFinite(viewerLat)) {
      const distance = calculateDistance(viewerLat, viewerLng, barLat, barLng);
      if (distance > MAX_CHECKIN_DISTANCE_METERS) {
        return res.status(400).json({ error: `距点位 ${Math.round(distance)} 米。需到点位 ${MAX_CHECKIN_DISTANCE_METERS} 米内，再打卡。` });
      }
    }

    let displayName = '匿名旅人';
    let avatar = '';
    let userId = null;
    let anonymousId = null;

    if (req.userId) {
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      displayName = user.username;
      avatar = user.avatar || '';
      userId = req.userId;
    } else if (req.anonymousId) {
      anonymousId = req.anonymousId;
    } else {
      return res.status(401).json({ error: '请先登录或提供匿名标识' });
    }

    const bar = await Bar.findOneAndUpdate(
      { amapPoiId },
      {
        $setOnInsert: {
          name,
          address: address || '',
          lng: barLng,
          lat: barLat
        }
      },
      { upsert: true, new: true }
    );

    bar.checkins.push({
      userId,
      anonymousId,
      displayName,
      avatar,
      lng: viewerLng || barLng,
      lat: viewerLat || barLat,
      note: (note || '').toString().slice(0, 140)
    });

    await bar.save();

    res.json({
      success: true,
      bar: {
        id: bar._id,
        amapPoiId: bar.amapPoiId,
        name: bar.name,
        checkinCount: bar.checkins.length
      },
      anonymousId
    });
  } catch (error) {
    console.error('Bar check-in error:', error);
    res.status(500).json({ error: '打卡失败，请重试' });
  }
};

const getBarCheckins = async (req, res) => {
  try {
    const { amapPoiId } = req.params;
    if (!amapPoiId) {
      return res.status(400).json({ error: '缺少 amapPoiId' });
    }

    const bar = await Bar.findOne({ amapPoiId }).lean();
    if (!bar) {
      return res.json({ bar: null, checkins: [] });
    }

    const checkins = (bar.checkins || [])
      .slice()
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map(c => ({
        id: c._id,
        username: c.displayName || '匿名旅人',
        avatar: c.avatar || '',
        note: c.note || '',
        createdAt: c.createdAt
      }));

    res.json({
      bar: {
        id: bar._id,
        amapPoiId: bar.amapPoiId,
        name: bar.name,
        checkinCount: checkins.length
      },
      checkins
    });
  } catch (error) {
    console.error('Get bar check-ins error:', error);
    res.status(500).json({ error: '获取打卡列表失败' });
  }
};

module.exports = {
  checkinAtBar,
  getBarCheckins
};
