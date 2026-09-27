const express = require('express');
const optionalAuth = require('../middlewares/optional-auth');
const { uploadSinglePhoto } = require('../middlewares/upload');
const {
  getCurrentEvent,
  upsertPet,
  getMe,
  checkin,
  createComposite,
  staticMap,
  amapConfig
} = require('../controllers/outie-controller');

const router = express.Router();

router.get('/event/current', getCurrentEvent);
router.get('/staticmap', staticMap);
router.get('/amap-config', amapConfig);
router.post('/pet', optionalAuth, upsertPet);
router.get('/me', optionalAuth, getMe);
router.post('/checkin', optionalAuth, checkin);
router.post('/composites', optionalAuth, uploadSinglePhoto, createComposite);

module.exports = router;
