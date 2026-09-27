const mongoose = require('mongoose');

const outieSpotSchema = new mongoose.Schema({
  key: { type: String, required: true },
  name: { type: String, required: true },
  zone: { type: String, default: '' },
  rewardName: { type: String, default: '' },
  lookId: { type: String, enum: ['music', 'art', 'market'], required: true },
  arrivalNote: { type: String, default: '' },
  lng: { type: Number, required: true },
  lat: { type: Number, required: true },
  radiusMeters: { type: Number, default: 200 }
}, { _id: false });

const outieEventSchema = new mongoose.Schema({
  key: { type: String, required: true, index: true, unique: true },
  name: { type: String, required: true },
  subtitle: { type: String, default: '' },
  active: { type: Boolean, default: false },
  spots: [outieSpotSchema],
  createdAt: { type: Date, default: Date.now }
});

const OutieEvent = mongoose.model('OutieEvent', outieEventSchema);

module.exports = OutieEvent;
