const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { passport } = require('../config/passport');
const config = require('../config/env');
const User = require('../models/user');
const { getClientIp, getDeviceFingerprint } = require('../utils/request-utils');

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const isDuplicateDeviceIdError = error => (
  error?.code === 11000
  && (
    error.keyPattern?.registrationDeviceId
    || (typeof error.message === 'string' && error.message.includes('registrationDeviceId'))
  )
);

const isDuplicateEmailError = error => (
  error?.code === 11000
  && (
    error.keyPattern?.email
    || (typeof error.message === 'string' && error.message.includes('email_1'))
  )
);

const register = async (req, res) => {
  try {
    const usernameInput = (req.body.username || '').trim();
    const emailRaw = req.body.email;
    const emailInput = typeof emailRaw === 'string' && emailRaw.trim().length
      ? emailRaw.trim().toLowerCase()
      : undefined;
    const passwordInput = req.body.password || '';

    if (!usernameInput || !passwordInput) {
      return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    if (passwordInput.length < 6) {
      return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    if (emailInput && !emailRegex.test(emailInput)) {
      return res.status(400).json({ error: '邮箱格式不正确' });
    }

    const searchConditions = [{ username: usernameInput }];
    if (emailInput) {
      searchConditions.push({ email: emailInput });
    }

    const existingUser = await User.findOne({ $or: searchConditions });
    if (existingUser) {
      return res.status(400).json({ error: emailInput ? '用户名或邮箱已被注册' : '用户名已被注册' });
    }

    const clientIp = getClientIp(req);
    const { deviceId, userAgent } = getDeviceFingerprint(req);

    const hashedPassword = await bcrypt.hash(passwordInput, config.bcryptSaltRounds);

    const userData = {
      username: usernameInput,
      password: hashedPassword,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(usernameInput)}`,
      registrationIp: clientIp,
      provider: 'local',
      registeredAt: new Date()
    };

    if (emailInput) {
      userData.email = emailInput;
    }
    if (deviceId) {
      userData.registrationDeviceId = deviceId;
    }
    if (userAgent) {
      userData.registrationUserAgent = userAgent;
    }

    const user = new User(userData);
    const originalDeviceId = userData.registrationDeviceId;

    try {
      await user.save();
    } catch (error) {
      if (isDuplicateDeviceIdError(error) && originalDeviceId) {
        console.warn('Duplicate registrationDeviceId detected, regenerating identifier', {
          username: usernameInput,
          deviceId: originalDeviceId
        });

        user.registrationDeviceId = `${originalDeviceId}::${crypto.randomUUID()}`;
        await user.save();
      } else {
        throw error;
      }
    }

    const token = jwt.sign({ userId: user._id }, config.jwtSecret, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Registration error:', error);

    const duplicateKey = error?.code === 11000 || (typeof error?.message === 'string' && error.message.includes('E11000 duplicate key error'));

    if (duplicateKey) {
      const keyPattern = error.keyPattern || {};
      const message = error.message || '';

      if (isDuplicateDeviceIdError(error)) {
        return res.status(400).json({ error: '该设备已注册账号，请使用已有账号登录' });
      }
      if (keyPattern.username || message.includes('username_1')) {
        return res.status(400).json({ error: '用户名已被注册' });
      }
      if (isDuplicateEmailError(error)) {
        return res.status(400).json({ error: '邮箱已被注册' });
      }
      if (keyPattern.githubId || message.includes('githubId')) {
        return res.status(400).json({ error: 'GitHub账号已绑定其他用户' });
      }
    }

    res.status(500).json({ error: '注册失败，请稍后重试' });
  }
};

const login = async (req, res) => {
  try {
    const usernameInput = (req.body.username || '').trim();
    const passwordInput = req.body.password || '';

    if (!usernameInput || !passwordInput) {
      return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    const user = await User.findOne({ username: usernameInput });
    if (!user || !user.password) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const isValidPassword = await bcrypt.compare(passwordInput, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    user.lastLoginAt = new Date();
    user.lastLoginIp = getClientIp(req);
    user.registrationUserAgent = user.registrationUserAgent || req.headers['user-agent'] || '';
    await user.save();

    const token = jwt.sign({ userId: user._id }, config.jwtSecret, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: '登录失败，请重试' });
  }
};

const verifyToken = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: { id: user._id, username: user.username, avatar: user.avatar } });
  } catch (error) {
    console.error('Verify token error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const beginGitHubAuth = (req, res) => {
  if (!config.github.clientId || !config.github.clientSecret) {
    return res.status(400).json({ error: '未配置 GitHub OAuth，无法使用 GitHub 登录' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

  const githubAuthUrl = `https://github.com/login/oauth/authorize?`
    + `client_id=${config.github.clientId}&`
    + `redirect_uri=${encodeURIComponent(config.getGitHubCallbackUrl())}&`
    + `scope=user:email&`
    + `state=${state}`;

  res.json({ url: githubAuthUrl, state });
};

const handleGitHubCallback = async (req, res, next) => {
  try {
    const { state } = req.query;

    if (!state || state !== req.session.oauthState) {
      console.error('State validation failed:', { received: state, expected: req.session.oauthState });
      delete req.session.oauthState;
      const redirectUrl = `${config.getFrontendBaseUrl()}/?error=invalid_state`;
      return res.redirect(redirectUrl);
    }

    delete req.session.oauthState;

    passport.authenticate('github', { session: false }, async (err, user, info) => {
      if (err || !user) {
        console.error('GitHub OAuth error:', err || info);
        const redirectUrl = `${config.getFrontendBaseUrl()}/?error=github_auth_failed`;
        return res.redirect(redirectUrl);
      }

      try {
        const token = jwt.sign({ userId: user._id }, config.jwtSecret, { expiresIn: '7d' });
        console.log('GitHub login successful for user:', user.username);
        const redirectUrl = `${config.getFrontendBaseUrl()}/?token=${token}`;
        return res.redirect(redirectUrl);
      } catch (tokenError) {
        console.error('Token generation error:', tokenError);
        const redirectUrl = `${config.getFrontendBaseUrl()}/?error=token_generation_failed`;
        return res.redirect(redirectUrl);
      }
    })(req, res, next);
  } catch (error) {
    console.error('GitHub OAuth callback error:', error);
    const redirectUrl = `${config.getFrontendBaseUrl()}/?error=auth_callback_error`;
    return res.redirect(redirectUrl);
  }
};

module.exports = {
  register,
  login,
  verifyToken,
  beginGitHubAuth,
  handleGitHubCallback
};
