const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const sharp = require('sharp');
const exifParser = require('exif-parser');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

// Passport OAuth
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');

// Load environment variables
dotenv.config();

// Validate required environment details early to avoid partial startup
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(name => !process.env[name]);
if (missingEnvVars.length) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

const sessionSecret = process.env.SESSION_SECRET || process.env.JWT_SECRET;
if (!sessionSecret) {
  console.error('SESSION_SECRET or JWT_SECRET must be defined for session management');
  process.exit(1);
}

const isProduction = process.env.NODE_ENV === 'production';

const normaliseOrigin = origin => {
  try {
    const url = new URL(origin);
    return `${url.protocol}//${url.host}`;
  } catch {
    return origin.trim();
  }
};

const toCleanString = value => {
  if (Array.isArray(value)) {
    const candidate = value.find(item => item != null && item !== '') ?? value[0];
    return candidate != null ? toCleanString(candidate) : '';
  }
  if (value == null) {
    return '';
  }
  return typeof value === 'string' ? value : String(value);
};

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Passport Configuration
const getGitHubCallbackURL = () => {
  // 根据环境自动生成回调URL
  if (process.env.NODE_ENV === 'development') {
    return `http://localhost:${process.env.PORT || 8444}/api/auth/github/callback`;
  } else {
    return process.env.GITHUB_CALLBACK_URL || `https://${process.env.DOMAIN || 'localhost'}/api/auth/github/callback`;
  }
};

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: getGitHubCallbackURL(),
    scope: ['user:email']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('GitHub profile:', {
        id: profile.id,
        username: profile.username,
        emails: profile.emails,
        photos: profile.photos
      });

      // 检查是否已有该GitHub用户
      let user = await User.findOne({ githubId: profile.id });

      if (user) {
        // 更新用户信息
        user.githubUsername = profile.username;
        if (profile.photos && profile.photos[0]) {
          user.avatar = profile.photos[0].value;
        }
        await user.save();
        return done(null, user);
      }

      // 创建新用户
      const email = (profile.emails && profile.emails[0]) ?
        profile.emails[0].value :
        `${profile.username}@github.local`; // 默认email

      const avatar = (profile.photos && profile.photos[0]) ?
        profile.photos[0].value :
        `https://api.dicebear.com/7.x/avataaars/svg?seed=${profile.username}`;

      user = new User({
        username: profile.username,
        email: email,
        avatar: avatar,
        provider: 'github',
        githubId: profile.id,
        githubUsername: profile.username
      });

      await user.save();
      console.log('Created new GitHub user:', user.username);
      return done(null, user);
    } catch (error) {
      console.error('GitHub strategy error:', error);
      return done(error, null);
    }
  }
));

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  password: String, // 密码哈希（传统注册用户）
  avatar: String,
  // OAuth相关字段
  provider: { type: String, enum: ['local', 'github'], default: 'local' },
  githubId: { type: String, unique: true, sparse: true },
  githubUsername: String,
  createdAt: { type: Date, default: Date.now }
});

const photoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  url: { type: String, required: true },
  caption: { type: String, required: true },
  lat: { type: Number, required: true },
  lng: { type: Number, required: true },
  location: {
    type: { type: String, enum: ['Point'], default: 'Point' },
    coordinates: { type: [Number], required: true }
  },
  exifLat: Number,
  exifLng: Number,
  distanceToUser: Number,
  locationInfo: {
    country: String,
    province: String,
    city: String,
    district: String,
    township: String,
    street: String,
    number: String,
    address: String,
    formattedAddress: String,
    landmark: String,
    nearestPoi: String
  },
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

photoSchema.index({ location: '2dsphere' });
photoSchema.index({ userId: 1, createdAt: -1 });

photoSchema.pre('save', function(next) {
  if (Number.isFinite(this.lat) && Number.isFinite(this.lng)) {
    this.location = {
      type: 'Point',
      coordinates: [this.lng, this.lat]
    };
  }
  next();
});

const User = mongoose.model('User', userSchema);
const Photo = mongoose.model('Photo', photoSchema);

// Initialize app
const app = express();

// Trust reverse proxies (Railway, Heroku, etc.) so secure cookies work correctly
app.set('trust proxy', 1);

const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || '')
    .split(',')
    .map(normaliseOrigin)
    .filter(Boolean)
);

if (!isProduction) {
  const devPort = process.env.PORT || 8444;
  allowedOrigins.add(`http://localhost:${devPort}`);
  allowedOrigins.add(`http://127.0.0.1:${devPort}`);
}

if (!allowedOrigins.size) {
  console.warn('No CORS origins configured; defaulting to allow all origins.');
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (!allowedOrigins.size || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    console.warn('Blocked CORS origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};

// Middleware
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
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
}));

// Session configuration for Passport
// Session configuration用于存储OAuth流程的临时state
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: parseInt(process.env.SESSION_COOKIE_MAX_AGE, 10) || 24 * 60 * 60 * 1000
  }
}));

// Passport middleware
app.use(passport.initialize());

// File upload setup
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE, 10) || 10 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const defaultTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif'];
    const allowedTypes = (process.env.ALLOWED_FILE_TYPES || '')
      .split(',')
      .map(type => type.trim())
      .filter(Boolean);
    const mimeWhitelist = allowedTypes.length ? allowedTypes : defaultTypes;

    if (mimeWhitelist.includes(file.mimetype)) {
      cb(null, true);
    } else {
      req.fileValidationError = `不支持的文件类型: ${file.mimetype || '未知'}`;
      cb(null, false);
    }
  }
});

const uploadSinglePhoto = (req, res, next) => {
  upload.single('photo')(req, res, err => {
    if (err) {
      if (err instanceof multer.MulterError) {
        const message = err.code === 'LIMIT_FILE_SIZE'
          ? '文件过大，超过允许的上传大小'
          : '文件上传失败，请重试';
        return res.status(400).json({ error: message });
      }
      return res.status(400).json({ error: err.message || '文件上传出错' });
    }
    return next();
  });
};

// Static files for uploaded photos (仅在非Railway环境需要)
// Railway使用容器持久化存储，始终提供静态文件服务
const uploadsDir = process.env.UPLOADS_DIR || 'uploads';
app.use(`/${uploadsDir}`, express.static(path.join(__dirname, uploadsDir)));

// Ensure uploads directory exists
const uploadsPath = path.join(__dirname, uploadsDir);
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
}

// Expose bundled静态页面，同时避免暴露整个项目目录
app.get('/website.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'website.html'));
});

if (process.env.NODE_ENV === 'development') {
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'website.html'));
  });
}

// JWT Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

// Auth Routes - Simple Registration and Login
app.post('/api/auth/register', async (req, res) => {
  try {
    const usernameInput = (req.body.username || '').trim();
    const emailInput = (req.body.email || '').trim().toLowerCase();
    const passwordInput = req.body.password || '';

    // Validate input
    if (!usernameInput || !emailInput || !passwordInput) {
      return res.status(400).json({ error: '用户名、邮箱和密码都是必需的' });
    }

    if (passwordInput.length < 6) {
      return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email: emailInput }, { username: usernameInput }] });
    if (existingUser) {
      return res.status(400).json({ error: '用户名或邮箱已被注册' });
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
    const hashedPassword = await bcrypt.hash(passwordInput, saltRounds);

    // Create user
    const user = new User({
      username: usernameInput,
      email: emailInput,
      password: hashedPassword,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(usernameInput)}`
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

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
    res.status(500).json({ error: '注册失败，请重试' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const usernameInput = (req.body.username || '').trim();
    const passwordInput = req.body.password || '';

    // Validate input
    if (!usernameInput || !passwordInput) {
      return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    // Find user
    const user = await User.findOne({ username: usernameInput });
    if (!user || !user.password) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(passwordInput, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

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
});

// Verify token
app.get('/api/auth/verify', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: { id: user._id, username: user.username, avatar: user.avatar } });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GitHub OAuth Routes
app.get('/api/auth/github', (req, res) => {
  // 生成state参数用于CSRF保护
  const state = crypto.randomBytes(16).toString('hex');

  // 存储state到session中（更安全的方式）
  req.session.oauthState = state;

  // 构建GitHub OAuth URL
  const githubAuthUrl = `https://github.com/login/oauth/authorize?` +
    `client_id=${process.env.GITHUB_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(getGitHubCallbackURL())}&` +
    `scope=user:email&` +
    `state=${state}`;

  res.json({
    url: githubAuthUrl,
    state: state
  });
});

app.get('/api/auth/github/callback',
  async (req, res) => {
    try {
      const { code, state } = req.query;

      console.log('GitHub callback received:', { code: !!code, state, sessionState: req.session.oauthState });

      // 验证state参数（使用session存储）
      if (!state || state !== req.session.oauthState) {
        console.error('State validation failed:', { received: state, expected: req.session.oauthState });
        const baseUrl = process.env.FRONTEND_URL || (process.env.NODE_ENV === 'development'
          ? `http://localhost:${process.env.PORT || 8444}`
          : `${process.env.PROTOCOL || 'https'}://${process.env.DOMAIN || 'localhost'}`);
        return res.redirect(`${baseUrl}/website.html?error=invalid_state`);
      }

      // 清除session中的state
      delete req.session.oauthState;

      // 使用Passport处理GitHub回调
      passport.authenticate('github', { session: false }, async (err, user, info) => {
        if (err || !user) {
          console.error('GitHub OAuth error:', err || info);
          const baseUrl = process.env.FRONTEND_URL || (process.env.NODE_ENV === 'development'
            ? `http://localhost:${process.env.PORT || 8444}`
            : `${process.env.PROTOCOL || 'https'}://${process.env.DOMAIN || 'localhost'}`);
          return res.redirect(`${baseUrl}/website.html?error=github_auth_failed`);
        }

        try {
          // 生成JWT token
          const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

          console.log('GitHub login successful for user:', user.username);

          // 重定向到前端页面，带上token参数
          const baseUrl = process.env.FRONTEND_URL || (process.env.NODE_ENV === 'development'
            ? `http://localhost:${process.env.PORT || 8444}`
            : `${process.env.PROTOCOL || 'https'}://${process.env.DOMAIN || 'localhost'}`);
          res.redirect(`${baseUrl}/website.html?token=${token}`);
        } catch (error) {
          console.error('Token generation error:', error);
          const baseUrl = process.env.FRONTEND_URL || (process.env.NODE_ENV === 'development'
            ? `http://localhost:${process.env.PORT || 8444}`
            : `${process.env.PROTOCOL || 'https'}://${process.env.DOMAIN || 'localhost'}`);
          res.redirect(`${baseUrl}/website.html?error=token_generation_failed`);
        }
      })(req, res);

    } catch (error) {
      console.error('GitHub OAuth callback error:', error);
      const baseUrl = process.env.FRONTEND_URL || (process.env.NODE_ENV === 'development'
        ? `http://localhost:${process.env.PORT || 8444}`
        : `${process.env.PROTOCOL || 'https'}://${process.env.DOMAIN || 'localhost'}`);
      res.redirect(`${baseUrl}/website.html?error=auth_callback_error`);
    }
  }
);

// Photo upload
app.post('/api/photos/upload', authenticate, uploadSinglePhoto, async (req, res) => {
  try {
    const { caption, userLat, userLng, locationSource } = req.body;
    const file = req.file;

    if (req.fileValidationError) {
      return res.status(400).json({ error: req.fileValidationError });
    }

    if (!file) return res.status(400).json({ error: 'No photo provided' });
    if (!caption) return res.status(400).json({ error: 'Caption required' });

    // Check daily upload limit (3 photos per day per user)
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const todayUploads = await Photo.countDocuments({
      userId: req.userId,
      createdAt: {
        $gte: today,
        $lt: tomorrow
      }
    });

    const dailyLimit = parseInt(process.env.DAILY_UPLOAD_LIMIT) || 3;
    if (todayUploads >= dailyLimit) {
      return res.status(400).json({ error: `每日最多只能上传${dailyLimit}张照片，请明天再来` });
    }

    // Parse EXIF
    let exif = { tags: {} };
    try {
      exif = exifParser.create(file.buffer).parse();
    } catch (parseError) {
      console.warn('EXIF解析失败，将视为无GPS信息:', parseError.message);
    }
    const gps = exif.tags || {};
    const hasExifCoords = Number.isFinite(gps.GPSLatitude) && Number.isFinite(gps.GPSLongitude);

    let photoLat;
    let photoLng;
    let distanceToUser = 0;

    const parsedUserLat = Number(userLat);
    const parsedUserLng = Number(userLng);
    const hasUserCoords = Number.isFinite(parsedUserLat) && Number.isFinite(parsedUserLng);

    if (hasExifCoords) {
      // 照片包含GPS信息
      photoLat = Number(gps.GPSLatitude);
      photoLng = Number(gps.GPSLongitude);
      if (gps.GPSLatitudeRef === 'S') photoLat = -photoLat;
      if (gps.GPSLongitudeRef === 'W') photoLng = -photoLng;

      // 验证照片GPS与用户位置的距离
      if (!hasUserCoords) {
        return res.status(400).json({ error: '缺少当前位置坐标，无法验证照片位置' });
      }

      distanceToUser = calculateDistance(parsedUserLat, parsedUserLng, photoLat, photoLng);
      const maxDistance = parseInt(process.env.MAX_DISTANCE_VERIFICATION) || 50;
      if (distanceToUser > maxDistance) {
        return res.status(400).json({ error: `照片拍摄位置与您当前所在位置相距过远 (${Math.round(distanceToUser)}米)，请确认您在照片拍摄地点附近` });
      }
    } else {
      // 照片不包含GPS信息
      if (locationSource === 'gps') {
        // 用户使用GPS定位，直接使用用户位置
        if (!hasUserCoords) {
          return res.status(400).json({ error: '缺少当前位置坐标，无法记录照片位置' });
        }
        photoLat = parsedUserLat;
        photoLng = parsedUserLng;
        distanceToUser = 0; // 距离为0，因为直接使用用户位置
      } else {
        // 用户使用IP定位，要求照片必须有GPS信息
        return res.status(400).json({ error: '为了确保照片真实性，请使用GPS定位后再上传照片，或选择包含位置信息的照片' });
      }
    }

    if (!Number.isFinite(photoLat) || !Number.isFinite(photoLng)) {
      return res.status(400).json({ error: '无法识别照片的地理位置信息' });
    }

    // Process image
    let imageUrl;

    // Railway环境：保存到文件系统（使用容器持久化存储）
    const filename = `${crypto.randomBytes(16).toString('hex')}.jpg`;
    const filepath = path.join(__dirname, 'uploads', filename);

    await sharp(file.buffer)
      .resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toFile(filepath);

    imageUrl = `/uploads/${filename}`;

    // 获取详细的位置信息，包括地标信息
    let locationInfo = {
      country: '',
      province: '',
      city: '',
      district: '',
      street: '',
      address: `${photoLat.toFixed(6)}, ${photoLng.toFixed(6)}`,
      formattedAddress: `${photoLat.toFixed(6)}, ${photoLng.toFixed(6)}`,
      landmark: '',
      nearestPoi: ''
    };

    // 获取逆地理编码信息和POI数据
    try {
      const apiKey = process.env.AMAP_REST_API_KEY || process.env.AMAP_WEB_API_KEY;
      if (apiKey) {
        const regeoResponse = await axios.get('https://restapi.amap.com/v3/geocode/regeo', {
          params: {
            key: apiKey,
            location: `${photoLng},${photoLat}`,
            extensions: 'all',
            radius: 1000,
            roadlevel: 1
          },
          timeout: 5000
        });

        if (regeoResponse.data.status === '1' && regeoResponse.data.regeocode) {
          const regeo = regeoResponse.data.regeocode;
          const addr = regeo.addressComponent;

          locationInfo = {
            country: toCleanString(addr.country),
            province: toCleanString(addr.province),
            city: toCleanString(addr.city),
            district: toCleanString(addr.district),
            township: toCleanString(addr.township),
            street: toCleanString(addr.streetNumber?.street),
            number: toCleanString(addr.streetNumber?.number),
            address: toCleanString(regeo.formatted_address) || `${photoLat.toFixed(6)}, ${photoLng.toFixed(6)}`,
            formattedAddress: toCleanString(regeo.formatted_address) || `${photoLat.toFixed(6)}, ${photoLng.toFixed(6)}`
          };

          // 添加POI信息
          if (regeo.pois && regeo.pois.length > 0) {
            // 按距离排序，选择最近的POI
            regeo.pois.sort((a, b) => parseFloat(a.distance || 1000) - parseFloat(b.distance || 1000));
            const nearestPoi = regeo.pois[0];

            const poiName = toCleanString(nearestPoi?.name);
            locationInfo.nearestPoi = poiName;
            locationInfo.landmark = poiName;
          }
        }
      }
    } catch (error) {
      console.log('逆地理编码失败，使用坐标作为地址:', error.message);
    }

    // Save to DB
    const photo = new Photo({
      userId: req.userId,
      url: imageUrl,
      caption,
      lat: photoLat,
      lng: photoLng,
      location: {
        type: 'Point',
        coordinates: [photoLng, photoLat]
      },
      exifLat: hasExifCoords ? photoLat : null, // 只有当照片包含GPS时才保存EXIF坐标
      exifLng: hasExifCoords ? photoLng : null,
      distanceToUser,
      locationInfo
    });

    await photo.save();

    res.json({ success: true, photo });
  } catch (error) {
    console.error('Upload error:', error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: '照片数据校验失败，请重试' });
    }
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get nearby photos
app.get('/api/photos/nearby', authenticate, async (req, res) => {
  try {
    const { lat, lng, radius = 300 } = req.query;
    const userLat = Number(lat);
    const userLng = Number(lng);
    const searchRadius = Math.max(0, Number(radius) || 0) || 300;

    if (!Number.isFinite(userLat) || !Number.isFinite(userLng)) {
      return res.status(400).json({ error: '缺少或无效的当前位置坐标' });
    }

    const nearbyPhotos = await Photo.aggregate([
      {
        $geoNear: {
          near: { type: 'Point', coordinates: [userLng, userLat] },
          key: 'location',
          distanceField: 'distance',
          maxDistance: searchRadius,
          spherical: true
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $project: {
          id: '$_id',
          url: 1,
          caption: 1,
          lat: 1,
          lng: 1,
          locationInfo: 1,
          distance: { $round: ['$distance', 0] },
          comments: { $size: '$comments' },
          username: { $arrayElemAt: ['$user.username', 0] },
          userAvatar: { $arrayElemAt: ['$user.avatar', 0] },
          createdAt: 1
        }
      }
    ]);

    res.json({ photos: nearbyPhotos });
  } catch (error) {
    console.error('Nearby photos error:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

// Get user's own photos
app.get('/api/photos/my', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const { page = 1, limit = 20 } = req.query;

    const photos = await Photo.find({ userId })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .populate('userId', 'username avatar');

    const total = await Photo.countDocuments({ userId });

    // 获取用户信息
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      photos: photos.map(photo => ({
        id: photo._id,
        url: photo.url,
        caption: photo.caption,
        lat: photo.lat,
        lng: photo.lng,
        locationInfo: photo.locationInfo,
        user: {
          username: user.username,
          avatar: user.avatar
        },
        comments: photo.comments.length,
        createdAt: photo.createdAt
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('My photos error:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

// Get photo details
app.get('/api/photos/:id', authenticate, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id).populate('userId', 'username avatar').populate('comments.userId', 'username avatar');
    if (!photo) return res.status(404).json({ error: 'Photo not found' });

    res.json({
      photo: {
        id: photo._id,
        url: photo.url,
        caption: photo.caption,
        lat: photo.lat,
        lng: photo.lng,
        locationInfo: photo.locationInfo,
        user: {
          username: photo.userId.username,
          avatar: photo.userId.avatar
        },
        createdAt: photo.createdAt,
        comments: photo.comments.map(c => {
          const commentUser = c.userId && typeof c.userId === 'object' && 'username' in c.userId ? c.userId : null;
          return {
            username: commentUser?.username || c.username,
            avatar: commentUser?.avatar || '',
            text: c.text,
            createdAt: c.createdAt
          };
        })
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Add comment
app.post('/api/photos/:id/comments', authenticate, async (req, res) => {
  try {
    const { comment } = req.body;
    if (!comment) return res.status(400).json({ error: 'Comment required' });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const photo = await Photo.findById(req.params.id);
    if (!photo) return res.status(404).json({ error: 'Photo not found' });

    photo.comments.push({
      userId: req.userId,
      username: user.username,
      text: comment
    });

    await photo.save();
    await photo.populate('comments.userId', 'username avatar');

    const latestComment = photo.comments[photo.comments.length - 1];

    res.json({
      success: true,
      comment: {
        username: latestComment.userId?.username || latestComment.username,
        avatar: latestComment.userId?.avatar || '',
        text: latestComment.text,
        createdAt: latestComment.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Distance calculation function
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const d = R * c * 1000; // meters
  return d;
}

// Amap configuration endpoint
app.get('/api/amap/config', (req, res) => {
  res.json({
    apiKey: process.env.AMAP_WEB_API_KEY, // Web端JS API密钥用于前端地图
    securityCode: process.env.AMAP_SECURITY_CODE,
    restApiKey: process.env.AMAP_REST_API_KEY // REST API密钥用于后端服务
  });
});

// IP定位接口
app.get('/api/location/ip', async (req, res) => {
  try {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                     req.headers['x-real-ip'] ||
                     req.connection.remoteAddress ||
                     req.socket.remoteAddress ||
                     req.ip ||
                     '127.0.0.1';

    console.log('IP定位请求，客户端IP:', clientIP);

    // 暂时返回默认位置信息，避免API调用失败
    res.json({
      success: true,
      location: {
        province: '上海市',
        city: '上海市',
        adcode: '310000',
        rectangle: '',
        ip: clientIP
      },
      source: 'ip'
    });

    // TODO: 后续获取有效API密钥后恢复高德API调用
    /*
    const ipToQuery = clientIP === '127.0.0.1' || clientIP === '::1' ? '' : clientIP;
    console.log('查询IP:', ipToQuery);

    const apiKey = process.env.AMAP_REST_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: '高德Web服务API密钥未配置' });
    }

    const response = await axios.get('https://restapi.amap.com/v3/ip', {
      params: {
        key: apiKey,
        ip: ipToQuery
      },
      timeout: 5000
    });

    if (response.data.status === '1') {
      const data = response.data;
      console.log('IP定位成功:', data);

      res.json({
        success: true,
        location: {
          province: data.province || '',
          city: data.city || '',
          adcode: data.adcode || '',
          rectangle: data.rectangle || '',
          ip: data.ip || ipToQuery
        },
        source: 'ip'
      });
    } else {
      console.error('IP定位失败:', response.data);
      res.status(400).json({
        error: response.data.info || 'IP定位失败',
        source: 'ip'
      });
    }
    */
  } catch (error) {
    console.error('IP定位错误:', error.message);
    res.status(500).json({
      error: 'IP定位服务暂时不可用',
      source: 'ip'
    });
  }
});

// 逆地理编码接口 - 获取详细地址信息
app.get('/api/location/regeo', async (req, res) => {
  try {
    const { lat, lng } = req.query;

    if (!lat || !lng) {
      return res.status(400).json({ error: '缺少经纬度参数' });
    }

    console.log('逆地理编码请求:', lat, lng);

    // 使用高德地图REST API进行逆地理编码
    const apiKey = process.env.AMAP_REST_API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: '高德地图API密钥未配置' });
    }

    try {
      const securityCode = process.env.AMAP_SECURITY_CODE;

      const requestParams = {
        key: apiKey,
        location: `${lng},${lat}`,
        extensions: 'all',
        radius: 1000,
        roadlevel: 1,
        ...(securityCode && { sec_code: securityCode })
      };

      console.log('高德地图API请求参数:', requestParams);

      const response = await axios.get('https://restapi.amap.com/v3/geocode/regeo', {
        params: requestParams,
        timeout: 5000
      });

      if (response.data.status === '1' && response.data.regeocode) {
        const regeocode = response.data.regeocode;
        console.log('逆地理编码成功');

        res.json({
          success: true,
          address: {
            formattedAddress: toCleanString(regeocode.formatted_address),
            country: toCleanString(regeocode.addressComponent?.country),
            province: toCleanString(regeocode.addressComponent?.province),
            city: toCleanString(regeocode.addressComponent?.city),
            district: toCleanString(regeocode.addressComponent?.district),
            township: toCleanString(regeocode.addressComponent?.township),
            street: toCleanString(regeocode.addressComponent?.streetNumber?.street),
            number: toCleanString(regeocode.addressComponent?.streetNumber?.number),
            adcode: toCleanString(regeocode.addressComponent?.adcode),
            citycode: toCleanString(regeocode.addressComponent?.citycode)
          },
          pois: regeocode.pois?.slice(0, 5) || [],
          roads: regeocode.roads?.slice(0, 3) || []
        });
      } else {
        console.error('逆地理编码失败:', response.data);
        res.status(400).json({
          success: false,
          error: response.data.info || '逆地理编码失败',
          details: response.data
        });
      }
    } catch (error) {
      console.error('逆地理编码错误:', error.message);
      res.status(500).json({
        success: false,
        error: '逆地理编码服务暂时不可用',
        details: error.message
      });
    }
  } catch (error) {
    console.error('逆地理编码请求处理错误:', error.message);
    res.status(500).json({
      success: false,
      error: '服务器内部错误',
      details: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Railway deployment support (容器化部署)
if (process.env.RAILWAY) {
  // Railway会自动处理端口监听，无需手动配置
  console.log('🚂 Running on Railway platform');
} else {
  // Local development server
  const PORT = process.env.PORT || 8444;
  const HOST = process.env.HOST || '0.0.0.0';

  if (process.env.NODE_ENV === 'development') {
    // Use HTTP for development to avoid SSL issues with OAuth
    app.listen(PORT, HOST, () => {
      console.log(`HTTP Server running on port ${PORT}`);
      console.log(`GitHub callback URL: http://localhost:${PORT}/api/auth/github/callback`);
      console.log(`Access website at: http://localhost:${PORT}/website.html`);
    });
  } else {
    app.listen(PORT, HOST, () => {
      console.log(`Server running on port ${PORT}`);
    });
  }
}
