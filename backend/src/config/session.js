const session = require('express-session');
const config = require('./env');

const createSessionMiddleware = () => session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: config.isProduction ? 'none' : 'lax',
    maxAge: config.sessionCookieMaxAge
  }
});

module.exports = createSessionMiddleware;
