const mongoose = require('mongoose');

const outiePetSchema = new mongoose.Schema({
  identityKey: { type: String, required: true, index: true, unique: true },
  name: { type: String, required: true },
  eventKey: { type: String, required: true, index: true },
  rewards: { type: Map, of: Date, default: {} },
  equipped: { type: String, default: 'base' },
  evolved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const OutiePet = mongoose.model('OutiePet', outiePetSchema);

module.exports = OutiePet;
