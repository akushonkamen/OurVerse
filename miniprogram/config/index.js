const CONFIG = {
  /**
   * 后端 API 基础地址。
   * 在实际部署时，将其替换为生产或测试环境的域名，
   * 并在微信小程序管理后台配置合法域名。
   */
  apiBaseUrl: 'http://localhost:8444',

  /**
   * 静态资源地址（如照片 CDN）。
   * 默认与 API 地址一致，可根据需要替换。
   */
  assetBaseUrl: 'http://localhost:8444'
};

const getConfig = () => CONFIG;

module.exports = {
  getConfig
};
