const OutieEvent = require('../models/outie-event');

const DEMO_EVENT = {
  key: 'weekend-exe',
  name: 'WEEKEND.EXE 周末出逃计划',
  subtitle: '到场打卡收集 · 静安站',
  active: true,
  spots: [
    {
      key: 'music',
      name: '霓虹舞台',
      zone: '音乐区',
      rewardName: '夜游耳机',
      lookId: 'music',
      arrivalNote: '主舞台东侧入口',
      address: '上海市静安区南京西路 1649 号',
      // 愚园路/常德路一带
      lng: 121.4426,
      lat: 31.224,
      radiusMeters: 200
    },
    {
      key: 'art',
      name: '像素画廊',
      zone: '展览区',
      rewardName: '数码眼镜',
      lookId: 'art',
      arrivalNote: '画廊一层服务台',
      address: '上海市静安区威海路 696 号',
      // 距 music 约 610 米
      lng: 121.4478,
      lat: 31.2272,
      radiusMeters: 200
    },
    {
      key: 'market',
      name: '怪趣市集',
      zone: '市集区',
      rewardName: '星星背包',
      lookId: 'market',
      arrivalNote: '中庭摊位区',
      address: '上海市静安区延安中路 823 号',
      // 距 art 约 610 米，距 music 约 740 米
      lng: 121.4501,
      lat: 31.2221,
      radiusMeters: 200
    }
  ]
};

// 幂等写入：force=true 强制刷新内容；默认仅在库里没有任何活动时才写入（生产安全）
const ensureDemoEvent = async ({ force = false } = {}) => {
  if (!force) {
    const total = await OutieEvent.countDocuments({});
    if (total > 0) return null;
  }
  const result = await OutieEvent.findOneAndUpdate(
    { key: DEMO_EVENT.key },
    {
      $set: {
        name: DEMO_EVENT.name,
        subtitle: DEMO_EVENT.subtitle,
        active: DEMO_EVENT.active,
        spots: DEMO_EVENT.spots
      },
      $setOnInsert: {
        createdAt: new Date()
      }
    },
    { upsert: true, new: true }
  );
  return result;
};

module.exports = { DEMO_EVENT, ensureDemoEvent };
