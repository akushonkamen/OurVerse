const { request } = require('../../utils/request');

Page({
  data: {
    serverHealthy: false,
    lastCheckedAt: ''
  },

  onShow() {
    this.pingServer();
  },

  async pingServer() {
    try {
      const data = await request({ url: '/health' });
      this.setData({
        serverHealthy: data.status === 'healthy',
        lastCheckedAt: data.timestamp || new Date().toISOString()
      });
    } catch (error) {
      console.warn('Health check failed', error);
      this.setData({
        serverHealthy: false,
        lastCheckedAt: new Date().toISOString()
      });
    }
  }
});
