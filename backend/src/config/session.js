const session = require('express-session');
const MongoStore = require('connect-mongo');
const config = require('./env');

const createSessionMiddleware = () => session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: config.isProduction
    ? MongoStore.create({
      mongoUrl: config.mongodbUri,
      collectionName: 'sessions',
      touchAfter: 24 * 3600
    })
    : undefined,
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
