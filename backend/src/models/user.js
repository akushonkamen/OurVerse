const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  password: String,
  avatar: String,
  provider: { type: String, enum: ['local', 'github'], default: 'local' },
  githubId: { type: String },
  githubUsername: String,
  createdAt: { type: Date, default: Date.now },
  registrationIp: { type: String, trim: true },
  registrationDeviceId: { type: String, trim: true },
  registrationUserAgent: { type: String },
  registeredAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date },
  lastLoginIp: { type: String, trim: true }
});

userSchema.index({ githubId: 1 }, {
  unique: true,
  partialFilterExpression: {
    provider: 'github',
    githubId: { $type: 'string' }
  }
});

userSchema.pre('save', function(next) {
  if (this.provider !== 'github' && this.githubId != null) {
    this.set('githubId', undefined);
  }
  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
