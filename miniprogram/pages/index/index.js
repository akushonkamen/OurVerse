const app = getApp();
Page({
  data: {
    bound: false, anonymousId: '', steps: 0, tokens: 0, mood: 60,
    petName: '', hint: '', bindInput: '', binding: false, syncing: false,
    showStarHint: false
  },
  onLoad() {
    try { this.anonId = wx.getStorageSync('anonymousId') || ''; } catch(e) {}
    app.anonymousId = this.anonId;
    const bound = Boolean(this.anonId);
    this.setData({ bound, anonymousId: this.anonId });
    if (bound) this.refresh();
    try {
      if (!wx.getStorageSync('starHintShown')) {
        this.setData({ showStarHint: true });
        wx.setStorageSync('starHintShown', true);
      }
    } catch(e) {}
  },
  toast(msg) { wx.showToast({ title: msg, icon: 'none', duration: 2000 }); },
  wxLogin() {
    return new Promise((resolve, reject) => {
      wx.login({ success: r => resolve(r.code), fail: () => reject(new Error('微信登录失败')) });
    });
  },
  ensureSession() {
    return this.wxLogin().then(code => new Promise((resolve, reject) => {
      wx.request({
        url: app.apiBase + '/outie/wx/session', method: 'POST', data: { code },
        success: r => r.data.wxToken ? resolve(r.data) : reject(new Error(r.data.error || '连接失败')),
        fail: () => reject(new Error('网络连接失败'))
      });
    }));
  },
  onBindInput(e) { this.bindCode = e.detail.value; },
  doBind() {
    if (!this.bindCode || this.bindCode.length < 6) { this.toast('输入 6 位绑定码'); return; }
    this.setData({ binding: true });
    this.ensureSession().then(s => new Promise((resolve, reject) => {
      wx.request({
        url: app.apiBase + '/outie/wx/bind', method: 'POST',
        data: { wxToken: s.wxToken, code: this.bindCode },
        success: r => r.data.success ? resolve(r.data) : reject(new Error(r.data.error || '绑定失败')),
        fail: () => reject(new Error('网络连接失败'))
      });
    })).then(() => {
      this.setData({ binding: false, bound: true });
      this.toast('绑定成功');
      this.refresh();
    }).catch(e => {
      this.setData({ binding: false });
      this.toast(e.message || '绑定失败');
    });
  },
  refresh() {
    wx.request({
      url: app.apiBase + '/outie/me', method: 'GET',
      header: { 'x-anonymous-id': this.anonId },
      success: r => {
        const p = r.data.pet;
        if (!p) return;
        this.setData({ petName: p.name, steps: p.stepsToday || 0, tokens: p.feedTokens || 0, mood: p.mood || 60 });
      }
    });
  },
  syncSteps() {
    if (this.data.syncing) return;
    this.setData({ syncing: true, hint: '' });
    this.ensureSession().then(s => new Promise((resolve, reject) => {
      wx.getWeRunData({
        success: r => {
          wx.request({
            url: app.apiBase + '/outie/wx/werun', method: 'POST',
            data: { wxToken: s.wxToken, encryptedData: r.encryptedData, iv: r.iv },
            success: resp => resp.data.error ? reject(new Error(resp.data.error)) : resolve(resp.data),
            fail: () => reject(new Error('网络连接失败'))
          });
        },
        fail: () => reject(new Error('需要微信运动授权'))
      });
    })).then(d => {
      this.setData({ steps: d.stepsToday, tokens: d.feedTokens, syncing: false, hint: '今日 ' + d.realSteps + ' 步 · +' + d.tokensAwarded + ' 包' });
      this.refresh();
    }).catch(e => {
      this.setData({ syncing: false, hint: e.message });
    });
  },
  dismissStar() { this.setData({ showStarHint: false }); },
  onShareAppMessage() {
    return { title: 'OUTIE — 到现场打卡，收集像素宠物', path: '/pages/index/index' };
  }
});
