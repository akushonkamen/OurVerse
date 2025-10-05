const express = require('express');
const {
  getIpLocation,
  getReverseGeocode
} = require('../controllers/location-controller');

const router = express.Router();

router.get('/ip', getIpLocation);
router.get('/regeo', getReverseGeocode);

module.exports = router;
