const { getConfig } = require('../config');

const request = (options = {}) => {
  const { apiBaseUrl } = getConfig();
  const token = wx.getStorageSync('token');

  return new Promise((resolve, reject) => {
    wx.request({
      url: `${apiBaseUrl}${options.url}`,
      method: options.method || 'GET',
      data: options.data || {},
      header: {
        'content-type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.header || {})
      },
      success(res) {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(res.data);
        } else {
          reject(res.data || { error: '请求失败' });
        }
      },
      fail(err) {
        reject(err);
      }
    });
  });
};

module.exports = {
  request
};
