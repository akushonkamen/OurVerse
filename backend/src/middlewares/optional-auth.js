const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { getOrCreateAnonymousId } = require('../services/anonymous-service');

const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (token) {
    jwt.verify(token, config.jwtSecret, (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      req.userId = decoded.userId;
      req.anonymousId = null;
      next();
    });
    return;
  }

  req.userId = null;
  req.anonymousId = getOrCreateAnonymousId(req);
  next();
};

module.exports = optionalAuth;
