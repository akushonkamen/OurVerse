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

// Passport OAuth
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');

// Load environment variables
dotenv.config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Passport Configuration
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
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

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String, // 密码哈希（传统注册用户）
  avatar: String,
  // OAuth相关字段
  provider: { type: String, enum: ['local', 'github'], default: 'local' },
  githubId: String,
  githubUsername: String,
  createdAt: { type: Date, default: Date.now }
});

const photoSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  url: String,
  caption: String,
  lat: Number,
  lng: Number,
  exifLat: Number,
  exifLng: Number,
  distanceToUser: Number,
  comments: [{
    userId: mongoose.Schema.Types.ObjectId,
    username: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Photo = mongoose.model('Photo', photoSchema);

// Initialize app
const app = express();

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://webapi.amap.com", "https://restapi.amap.com", "blob:"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://webapi.amap.com", "https://restapi.amap.com", "https://vdata.amap.com"],
      workerSrc: ["'self'", "blob:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Session configuration for Passport
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // 本地开发用false，生产环境用true
    maxAge: 24 * 60 * 60 * 1000 // 24小时
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// File upload setup
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image!'), false);
    }
  }
});

// Static files for uploaded photos
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Static files for website (development only)
if (process.env.NODE_ENV === 'development') {
  app.use(express.static(path.join(__dirname)));
}

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
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
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: '用户名、邮箱和密码都是必需的' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: '用户名或邮箱已被注册' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`
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
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
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
  // 生成state参数用于CSRF保护，并存储在内存中（临时解决方案）
  const state = crypto.randomBytes(16).toString('hex');

  // 临时存储state（在生产环境中应该使用数据库）
  global.tempOAuthState = state;

  // 构建GitHub OAuth URL
  const githubAuthUrl = `https://github.com/login/oauth/authorize?` +
    `client_id=${process.env.GITHUB_CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(process.env.GITHUB_CALLBACK_URL)}&` +
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

      console.log('GitHub callback received:', { code: !!code, state, tempState: global.tempOAuthState });

      // 验证state参数（使用临时存储）
      if (!state || state !== global.tempOAuthState) {
        console.error('State validation failed:', { received: state, expected: global.tempOAuthState });
        return res.redirect(`${process.env.NODE_ENV === 'development' ? 'http' : 'https'}://localhost:8444/website.html?error=invalid_state`);
      }

      // 清除临时state
      delete global.tempOAuthState;

      // 使用Passport处理GitHub回调
      passport.authenticate('github', { session: false }, async (err, user, info) => {
        if (err || !user) {
          console.error('GitHub OAuth error:', err || info);
          return res.redirect(`${process.env.NODE_ENV === 'development' ? 'http' : 'https'}://localhost:8444/website.html?error=github_auth_failed`);
        }

        try {
          // 生成JWT token
          const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

          console.log('GitHub login successful for user:', user.username);

          // 重定向到前端页面，带上token参数
          res.redirect(`${process.env.NODE_ENV === 'development' ? 'http' : 'https'}://localhost:8444/website.html?token=${token}`);
        } catch (error) {
          console.error('Token generation error:', error);
          res.redirect(`${process.env.NODE_ENV === 'development' ? 'http' : 'https'}://localhost:8444/website.html?error=token_generation_failed`);
        }
      })(req, res);

    } catch (error) {
      console.error('GitHub OAuth callback error:', error);
      res.redirect(`${process.env.NODE_ENV === 'development' ? 'http' : 'https'}://localhost:8444/website.html?error=auth_callback_error`);
    }
  }
);

// Photo upload
app.post('/api/photos/upload', authenticate, upload.single('photo'), async (req, res) => {
  try {
    const { caption, userLat, userLng } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ error: 'No photo provided' });
    if (!caption) return res.status(400).json({ error: 'Caption required' });

    // Parse EXIF
    const parser = exifParser.create(file.buffer);
    const exif = parser.parse();
    const gps = exif.tags;

    let exifLat, exifLng;
    if (gps.GPSLatitude && gps.GPSLongitude) {
      exifLat = gps.GPSLatitude;
      exifLng = gps.GPSLongitude;
      if (gps.GPSLatitudeRef === 'S') exifLat = -exifLat;
      if (gps.GPSLongitudeRef === 'W') exifLng = -exifLng;
    } else {
      return res.status(400).json({ error: 'Photo must contain GPS location data' });
    }

    // Verify distance (max 50m)
    const distance = calculateDistance(parseFloat(userLat), parseFloat(userLng), exifLat, exifLng);
    if (distance > 50) {
      return res.status(400).json({ error: `Photo location too far from user (${Math.round(distance)}m)` });
    }

    // Process image
    const filename = `${crypto.randomBytes(16).toString('hex')}.jpg`;
    const filepath = path.join(__dirname, 'uploads', filename);

    await sharp(file.buffer)
      .resize({ width: 800, withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toFile(filepath);

    // Save to DB
    const photo = new Photo({
      userId: req.userId,
      url: `/uploads/${filename}`,
      caption,
      lat: exifLat,
      lng: exifLng,
      exifLat,
      exifLng,
      distanceToUser: distance
    });

    await photo.save();

    res.json({ success: true, photo });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get nearby photos
app.get('/api/photos/nearby', authenticate, async (req, res) => {
  try {
    const { lat, lng, radius = 300 } = req.query;
    const userLat = parseFloat(lat);
    const userLng = parseFloat(lng);

    const nearbyPhotos = await Photo.aggregate([
      {
        $geoNear: {
          near: { type: 'Point', coordinates: [userLng, userLat] },
          distanceField: 'distance',
          maxDistance: parseInt(radius),
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
          distance: { $round: ['$distance', 0] },
          comments: { $size: '$comments' },
          username: { $arrayElemAt: ['$user.username', 0] }
        }
      }
    ]);

    res.json({ photos: nearbyPhotos });
  } catch (error) {
    console.error('Nearby photos error:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

// Get photo details
app.get('/api/photos/:id', authenticate, async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id).populate('comments.userId', 'username avatar');
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    
    res.json({ 
      photo: {
        id: photo._id,
        url: photo.url,
        caption: photo.caption,
        lat: photo.lat,
        lng: photo.lng,
        comments: photo.comments.map(c => ({
          username: c.username,
          text: c.text,
          createdAt: c.createdAt
        }))
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

    res.json({ success: true });
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

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Start server
const PORT = process.env.PORT || 8444;

if (process.env.NODE_ENV === 'development') {
  // Use HTTP for development to avoid SSL issues with OAuth
  app.listen(PORT, () => {
    console.log(`HTTP Server running on port ${PORT}`);
    console.log(`GitHub callback URL: http://localhost:${PORT}/api/auth/github/callback`);
    console.log(`Access website at: http://localhost:${PORT}/website.html`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}
