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
// Always allow www.our-verse.com for development testing
allowedOrigins.add('https://www.our-verse.com');

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
      connectSrc: ["'self'", "https://*.amap.com", "http://localhost:8444"],
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

const websitePath = path.resolve(__dirname, '..', 'public', 'website.html');
if (fs.existsSync(websitePath)) {
  app.get('/website.html', (req, res) => {
    res.sendFile(websitePath);
  });

  // 在生产环境下也支持根路径访问
  app.get('/', (req, res) => {
    res.sendFile(websitePath);
  });
}

app.use('/api', routes);

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

module.exports = app;
