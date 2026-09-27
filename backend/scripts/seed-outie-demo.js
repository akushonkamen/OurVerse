#!/usr/bin/env node

/**
 * Seed (upsert) the OUTIE demo event WEEKEND.EXE with three spots around
 * Jing'an, Shanghai. Idempotent: safe to run repeatedly.
 *
 * Usage: node backend/scripts/seed-outie-demo.js
 */

const mongoose = require('mongoose');
const { connectDatabase } = require('../src/config/database');
const OutieEvent = require('../src/models/outie-event');

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
      // 距 art 约 610 米，距 music 约 740 米
      lng: 121.4501,
      lat: 31.2221,
      radiusMeters: 200
    }
  ]
};

const seedOutieDemo = async () => {
  await connectDatabase();

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

  console.log(`Seeded OUTIE demo event: ${result.key} (${result.name}), spots: ${result.spots.length}`);

  await mongoose.disconnect();
  console.log('Done.');
};

seedOutieDemo().catch(error => {
  console.error('Seed failed:', error);
  process.exit(1);
});
