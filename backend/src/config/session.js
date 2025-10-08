const session = require('express-session');
const config = require('./env');

const createSessionMiddleware = () => session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  // 在生产环境中使用更稳定的session存储
  store: config.isProduction ? undefined : undefined, // 暂时使用默认memory store进行测试
  cookie: {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'lax', // 统一使用'lax'以确保session cookie在同一域名下正常工作
    maxAge: config.sessionCookieMaxAge,
    path: '/',
    domain: config.isProduction ? config.domain : undefined // 明确设置domain
  }
});

module.exports = createSessionMiddleware;
