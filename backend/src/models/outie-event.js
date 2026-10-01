const mongoose = require('mongoose');

// 活动装扮插件规范：体形 + 颜色 + 花纹 + 配件，由前端像素宠物引擎渲染
const outieLookSpecSchema = new mongoose.Schema({
  name: { type: String, default: '' },
  shape: { type: String, enum: ['blob', 'cat', 'bear', 'bunny'], default: 'blob' },
  body: { type: String, default: '#a3463c' },
  accent: { type: String, default: '#41597e' },
  pattern: { type: String, enum: ['solid', 'spots', 'stripes'], default: 'solid' },
  accessory: {
    type: String,
    enum: ['none', 'headphones', 'glasses', 'bag', 'crown', 'bow', 'scarf', 'cap', 'flower', 'bell'],
    default: 'none'
  }
}, { _id: false });

const outieSpotSchema = new mongoose.Schema({
  key: { type: String, required: true },
  name: { type: String, required: true },
  zone: { type: String, default: '' },
  rewardName: { type: String, default: '' },
  // 旧版内置造型（music/art/market）；新活动用 look 插件规范
  lookId: { type: String, default: '' },
  look: { type: outieLookSpecSchema, default: null },
  arrivalNote: { type: String, default: '' },
  amapPoiId: { type: String, default: '' },
  address: { type: String, default: '' },
  lng: { type: Number, required: true },
  lat: { type: Number, required: true },
  radiusMeters: { type: Number, default: 200 }
}, { _id: false });

const outieEventSchema = new mongoose.Schema({
  key: { type: String, required: true, index: true, unique: true },
  name: { type: String, required: true },
  subtitle: { type: String, default: '' },
  active: { type: Boolean, default: false },
  voucherEnabled: { type: Boolean, default: false },
  organizerKey: { type: String, default: '', index: true },
  coverUrl: { type: String, default: '' },
  spots: [outieSpotSchema],
  createdAt: { type: Date, default: Date.now }
});

const OutieEvent = mongoose.model('OutieEvent', outieEventSchema);

module.exports = OutieEvent;
