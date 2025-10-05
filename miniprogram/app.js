const { getConfig } = require('./config');

App({
  globalData: {
    config: getConfig()
  },

  onLaunch() {
    const { apiBaseUrl } = this.globalData.config;
    if (!apiBaseUrl) {
      console.warn('未设置后端 API 地址，请在 miniprogram/config/index.js 中配置');
    }
  }
});
