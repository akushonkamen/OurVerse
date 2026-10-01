const mongoose = require('mongoose');

// 到店凭证：打卡签发的 6 位核销码，商家（活动发布者）核销
const voucherSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  eventKey: { type: String, required: true, index: true },
  spotKey: { type: String, default: '' },
  identityKey: { type: String, required: true, index: true },
  petName: { type: String, default: '' },
  redeemedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Voucher', voucherSchema);
