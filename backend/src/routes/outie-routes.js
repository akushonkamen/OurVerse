const express = require('express');
const optionalAuth = require('../middlewares/optional-auth');
const { uploadSinglePhoto } = require('../middlewares/upload');
const {
  getCurrentEvent,
  upsertPet,
  getMe,
  checkin,
  feedPet,
  touchPet,
  syncSteps,
  createComposite,
  staticMap,
  getMapTile,
  createEvent,
  listMyEvents,
  listAllEvents,
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
router.get('/events/all', listAllEvents);
router.get('/my-events', optionalAuth, listMyEvents);
router.get('/events/:key', getEventDetail);
router.post('/events/:key/promo', optionalAuth, uploadSinglePhoto, uploadEventPromo);
router.post('/pet', optionalAuth, upsertPet);
router.post('/pet/feed', optionalAuth, feedPet);
router.post('/pet/touch', optionalAuth, touchPet);
router.post('/steps/sync', optionalAuth, syncSteps);
router.get('/me', optionalAuth, getMe);
router.post('/checkin', optionalAuth, checkin);
router.post('/composites', optionalAuth, uploadSinglePhoto, createComposite);

module.exports = router;
