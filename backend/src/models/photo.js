const mongoose = require('mongoose');

const locationInfoSchema = new mongoose.Schema({
  country: String,
  province: String,
  city: String,
  district: String,
  township: String,
  street: String,
  number: String,
  address: String,
  formattedAddress: String,
  landmark: String,
  nearestPoi: String
}, { _id: false });

const commentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  text: String,
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const photoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  url: { type: String, required: true },
  caption: { type: String, required: true },
  lat: { type: Number, required: true },
  lng: { type: Number, required: true },
  location: {
    type: { type: String, enum: ['Point'], default: 'Point' },
    coordinates: { type: [Number], required: true }
  },
  exifLat: Number,
  exifLng: Number,
  distanceToUser: Number,
  locationInfo: locationInfoSchema,
  comments: [commentSchema],
  createdAt: { type: Date, default: Date.now }
});

photoSchema.index({ location: '2dsphere' });
photoSchema.index({ userId: 1, createdAt: -1 });

photoSchema.pre('save', function(next) {
  if (Number.isFinite(this.lat) && Number.isFinite(this.lng)) {
    this.location = {
      type: 'Point',
      coordinates: [this.lng, this.lat]
    };
  }
  next();
});

const Photo = mongoose.model('Photo', photoSchema);

module.exports = Photo;
