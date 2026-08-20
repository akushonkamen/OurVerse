const express = require('express');
const optionalAuth = require('../middlewares/optional-auth');
const { checkinAtBar, getBarCheckins } = require('../controllers/bar-controller');

const router = express.Router();

router.post('/checkin', optionalAuth, checkinAtBar);
router.get('/:amapPoiId/checkins', getBarCheckins);

module.exports = router;
