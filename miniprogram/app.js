App({
  onLaunch() {
    this.apiBase = 'https://our-verse.com/api';
    try { this.anonymousId = wx.getStorageSync('anonymousId') || ''; } catch (e) { this.anonymousId = ''; }
  }
});
