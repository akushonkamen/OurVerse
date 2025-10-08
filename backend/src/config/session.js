const session = require('express-session');
const config = require('./env');

const createSessionMiddleware = () => session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'lax', // 统一使用'lax'以确保session cookie在同一域名下正常工作
    maxAge: config.sessionCookieMaxAge,
    path: '/'
  }
});

module.exports = createSessionMiddleware;
