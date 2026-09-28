const mongoose = require('mongoose');

// OUTIE 宠物：跨活动存在的长期角色。
// rewards 以活动为分组：{ [eventKey]: { [spotKey]: Date } }（Mixed，需手动 markModified）
// evolvedEvents 记录每个已解锁限定形态的活动 key。
const outiePetSchema = new mongoose.Schema({
  identityKey: { type: String, required: true, index: true },
  name: { type: String, default: '' },
  rewards: { type: {}, default: {} },
  evolvedEvents: { type: [String], default: [] },
  equipped: { type: String, default: 'base' },
  // 旧字段：仅保留兼容历史数据（读入时惰性迁移到 rewards/evolvedEvents）
  eventKey: { type: String, default: '' },
  evolved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

outiePetSchema.pre('save', function (next) {
  if (this.isModified('rewards')) this.markModified('rewards');
  next();
});

const OutiePet = mongoose.model('OutiePet', outiePetSchema);

module.exports = OutiePet;
