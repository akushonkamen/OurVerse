const mongoose = require('mongoose');

const barCheckinSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  anonymousId: { type: String, default: null },
  displayName: { type: String, default: '' },
  avatar: { type: String, default: '' },
  lng: { type: Number, required: true },
  lat: { type: Number, required: true },
  note: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
}, { _id: true });

const barSchema = new mongoose.Schema({
  amapPoiId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  address: { type: String, default: '' },
  lng: { type: Number, required: true },
  lat: { type: Number, required: true },
  checkins: [barCheckinSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

barSchema.index({ lat: 1, lng: 1 });
barSchema.index({ 'checkins.anonymousId': 1, 'checkins.createdAt': -1 }, { sparse: true });
barSchema.index({ 'checkins.userId': 1, 'checkins.createdAt': -1 }, { sparse: true });

barSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

const Bar = mongoose.model('Bar', barSchema);

module.exports = Bar;
