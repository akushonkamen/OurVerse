const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const config = require('./config/env');
const { normaliseOrigin } = require('./utils/string-utils');
const createSessionMiddleware = require('./config/session');
const routes = require('./routes');
const { passport, applyPassportStrategies } = require('./config/passport');

applyPassportStrategies();

const app = express();

app.set('trust proxy', 1);

const allowedOrigins = new Set(
  config.allowedOriginsRaw
    .split(',')
    .map(normaliseOrigin)
    .filter(Boolean)
);

if (!config.isProduction) {
  allowedOrigins.add(`http://localhost:${config.port}`);
  allowedOrigins.add(`http://127.0.0.1:${config.port}`);
}

if (!allowedOrigins.size) {
  console.warn('No CORS origins configured; defaulting to allow all origins.');
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    if (!allowedOrigins.size || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    console.warn('Blocked CORS origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://*.amap.com", "blob:"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://*.amap.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:", "https://*.amap.com"],
      connectSrc: ["'self'", "https://*.amap.com"],
      workerSrc: ["'self'", "blob:"],
      fontSrc: ["'self'", "https://*.amap.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));
app.use(cors(corsOptions));
app.use(compression());
app.use(express.json());
app.use(rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests
}));
app.use(createSessionMiddleware());
app.use(passport.initialize());

const uploadsPath = path.resolve(__dirname, '..', config.uploadsDir);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
}
app.use(`/${config.uploadsDir}`, express.static(uploadsPath));

// 根路径处理 - 返回简单的API信息
app.get('/', (req, res) => {
  res.json({
    message: 'OurVerse API Server',
    version: '1.0.0',
    docs: '/api',
    health: '/health'
  });
});

app.use('/api', routes);

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

module.exports = app;
