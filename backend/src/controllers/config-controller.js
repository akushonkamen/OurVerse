const config = require('../config/env');

const getAmapConfig = (req, res) => {
  res.json({
    apiKey: config.amap.webApiKey,
    securityCode: config.amap.securityCode,
    restApiKey: config.amap.restApiKey
  });
};

module.exports = {
  getAmapConfig
};
