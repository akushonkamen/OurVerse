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
  getMapTile,
  createEvent,
  listMyEvents,
  nearbyEvents,
  getEventDetail,
  uploadEventPromo,
  amapConfig
} = require('../controllers/outie-controller');

const router = express.Router();

router.get('/event/current', getCurrentEvent);
router.get('/staticmap', staticMap);
router.get('/amap-config', amapConfig);
router.get('/tiles/:z/:x/:y', getMapTile);
router.post('/events', optionalAuth, createEvent);
router.get('/events/nearby', nearbyEvents);
router.get('/my-events', optionalAuth, listMyEvents);
router.get('/events/:key', getEventDetail);
router.post('/events/:key/promo', optionalAuth, uploadSinglePhoto, uploadEventPromo);
router.post('/pet', optionalAuth, upsertPet);
router.get('/me', optionalAuth, getMe);
router.post('/checkin', optionalAuth, checkin);
router.post('/composites', optionalAuth, uploadSinglePhoto, createComposite);

module.exports = router;
