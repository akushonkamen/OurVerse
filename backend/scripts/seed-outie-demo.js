#!/usr/bin/env node

/**
 * Seed (upsert) the OUTIE demo event WEEKEND.EXE. Idempotent: safe to run repeatedly.
 *
 * Usage: node backend/scripts/seed-outie-demo.js
 * 服务端也可在 .env 设 OUTIE_AUTOSEED=true，由启动流程自动写入。
 */

const mongoose = require('mongoose');
const { connectDatabase } = require('../src/config/database');
const { ensureDemoEvent } = require('../src/services/outie-seed-service');

const main = async () => {
  await connectDatabase();
  const result = await ensureDemoEvent({ force: true });
  console.log(`Seeded OUTIE demo event: ${result.key} (${result.name}), spots: ${result.spots.length}`);
  await mongoose.disconnect();
  console.log('Done.');
};

main().catch(error => {
  console.error('Seed failed:', error);
  process.exit(1);
});
