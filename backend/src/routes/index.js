const express = require('express');
const authRoutes = require('./auth-routes');
const photoRoutes = require('./photo-routes');
const locationRoutes = require('./location-routes');
const barRoutes = require('./bar-routes');
const { getAmapConfig } = require('../controllers/config-controller');

const router = express.Router();

router.use('/auth', authRoutes);
router.use('/photos', photoRoutes);
router.use('/location', locationRoutes);
router.use('/bars', barRoutes);
router.get('/amap/config', getAmapConfig);

module.exports = router;
