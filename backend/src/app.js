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
    if (!config.isProduction) {
      console.log('CORS check for origin:', origin);
      console.log('Allowed origins:', Array.from(allowedOrigins));
    }
    if (!origin) {
      if (!config.isProduction) {
        console.log('No origin header, allowing');
      }
      return callback(null, true);
    }
    if (!allowedOrigins.size || allowedOrigins.has(origin)) {
      if (!config.isProduction) {
        console.log('Origin allowed:', origin);
      }
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
      imgSrc: ["'self'", "data:", "https:", "blob:", "https://*.amap.com", "http://localhost:8444"],
      connectSrc: ["'self'", "https://*.amap.com", "http://localhost:8444"],
      workerSrc: ["'self'", "blob:"],
      fontSrc: ["'self'", "https://*.amap.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors(corsOptions));
app.use(compression());

const defaultBodyPayloadLimit = 1 * 1024 * 1024;
const unlimitedBodyPayloadLimit = '10gb';

if (Number.isFinite(config.maxFileSize) && config.maxFileSize > 0) {
  const bodyPayloadLimit = Math.max(config.maxFileSize, defaultBodyPayloadLimit);
  app.use(express.json({ limit: bodyPayloadLimit }));
  app.use(express.urlencoded({ limit: bodyPayloadLimit, extended: true }));
} else {
  app.use(express.json({ limit: unlimitedBodyPayloadLimit }));
  app.use(express.urlencoded({ limit: unlimitedBodyPayloadLimit, extended: true }));
}
// 限流只作用于 API：静态资源（vendor/uploads）与地图瓦片代理单独高限额，避免刷几次页面就 429
const apiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests
});
const assetLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: Math.max(config.rateLimit.maxRequests * 20, 2000)
});
app.use('/api/outie/tiles', assetLimiter);
app.use('/vendor', assetLimiter);
app.use('/api', apiLimiter);
app.use(createSessionMiddleware());
app.use(passport.initialize());

const uploadsPath = path.resolve(__dirname, '..', config.uploadsDir);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
}
app.use(`/${config.uploadsDir}`, express.static(uploadsPath));

// 自托管的前端静态资源（maplibre 等），生产与本地同源可用
app.use('/vendor', express.static(path.resolve(__dirname, '..', 'public', 'vendor'), {
  maxAge: '7d',
  immutable: true
}));

const websitePath = path.resolve(__dirname, '..', 'public', 'website.html');
if (fs.existsSync(websitePath)) {
  app.get('/website.html', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.sendFile(websitePath);
  });
}

// OUTIE 网页前端作为站点首页（源文件在仓库 web/）；缺失时回退旧官网
const outieWebPath = path.resolve(__dirname, '..', '..', 'web', 'index.html');
const homePagePath = fs.existsSync(outieWebPath) ? outieWebPath : websitePath;
if (fs.existsSync(homePagePath)) {
  // 在生产环境下也支持根路径访问；页面本身禁缓存，避免更新后浏览器滞留旧版
  app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(homePagePath);
  });
}

// OUTIE PWA 静态资源：安装清单与像素图标（与 index.html 同仓库 web/ 目录）
app.use('/icons', express.static(path.resolve(__dirname, '..', '..', 'web', 'icons'), {
  maxAge: '7d',
  immutable: true
}));
const outieManifestPath = path.resolve(__dirname, '..', '..', 'web', 'manifest.webmanifest');
if (fs.existsSync(outieManifestPath)) {
  app.get('/manifest.webmanifest', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.type('application/manifest+json');
    res.sendFile(outieManifestPath);
  });
}

app.use('/api', routes);

// /api 未匹配路由一律回 JSON，别让前端收到 HTML 的 Cannot GET
app.use('/api', (req, res) => {
  res.status(404).json({ error: '接口不存在' });
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 全局错误兜底放最后：/api 出错统一 JSON（multer/中间件抛错此前会漏成 HTML 500）
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[app] unhandled error:', err && err.message);
  if (req.path.startsWith('/api') || req.headers.accept?.includes('application/json')) {
    return res.status(err.status || 500).json({ error: err.status ? err.message : '服务开小差了，请稍后重试' });
  }
  res.status(500).send('Internal Server Error');
});

module.exports = app;
