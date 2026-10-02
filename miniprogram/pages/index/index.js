const app = getApp();
Page({
  data: { bound: false, anonymousId: '', steps: 0, tokens: 0, mood: 60, petName: '', log: '' },
  onLoad() {
    this.setData({ anonymousId: app.anonymousId, bound: Boolean(app.anonymousId) });
    if (app.anonymousId) this.refresh();
  },
  log(msg) { this.setData({ log: msg }); },
  wxLogin() {
    return new Promise((resolve, reject) => {
      wx.login({
        success: r => resolve(r.code),
        fail: () => reject(new Error('微信登录失败。请重试'))
      });
    });
  },
  async ensureSession() {
    const code = await this.wxLogin();
    return new Promise((resolve, reject) => {
      wx.request({
        url: app.apiBase + '/outie/wx/session',
        method: 'POST',
        data: { code },
        success: r => (r.data.wxToken ? resolve(r.data) : reject(new Error(r.data.error || '连接失败。请重试'))),
        fail: () => reject(new Error('网络连接失败。请检查网络后重试'))
      });
    });
  },
  async onBindInput(e) { this.bindCode = e.detail.value; },
  async doBind() {
    if (!this.bindCode) { this.log('请在 OUTIE 网页生成 6 位绑定码'); return; }
    try {
      const s = await this.ensureSession();
      await new Promise((resolve, reject) => {
        wx.request({
          url: app.apiBase + '/outie/wx/bind',
          method: 'POST',
          data: { wxToken: s.wxToken, code: this.bindCode },
          success: r => (r.data.success ? resolve(r.data) : reject(new Error(r.data.error || '绑定失败'))),
          fail: () => reject(new Error('网络失败'))
        });
      });
      this.setData({ bound: true, anonymousId: app.anonymousId });
      this.log('绑定成功');
      this.refresh();
    } catch (e) { this.log('绑定失败：' + e.message); }
  },
  async refresh() {
    wx.request({
      url: app.apiBase + '/outie/me',
      method: 'GET',
      header: { 'x-anonymous-id': app.anonymousId },
      success: r => {
        const p = r.data.pet;
        if (!p) { this.log('还未领养宠物。请在 OUTIE 网页领养'); return; }
        this.setData({ petName: p.name, steps: p.stepsToday || 0, tokens: p.feedTokens || 0, mood: p.mood || 60 });
      }
    });
  },
  async syncSteps() {
    this.log('同步中…');
    try {
      const s = await this.ensureSession();
      wx.getWeRunData({
        success: r => {
          wx.request({
            url: app.apiBase + '/outie/wx/werun',
            method: 'POST',
            data: { wxToken: s.wxToken, encryptedData: r.encryptedData, iv: r.iv },
            success: resp => {
              const d = resp.data;
              if (d.error) { this.log(d.error); return; }
              this.setData({ steps: d.stepsToday, tokens: d.feedTokens });
              this.log('今日微信步数 ' + d.realSteps + ' 步。计入 ' + d.credited + ' 步');
              this.refresh();
            },
            fail: () => this.log('网络失败')
          });
        },
        fail: () => this.log('需要微信运动授权。点右上角「设置」，开启授权')
      });
    } catch (e) { this.log(e.message); }
  }
});
