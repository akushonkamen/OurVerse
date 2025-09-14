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
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

// Load environment variables
dotenv.config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  avatar: String,
  provider: String,
  providerId: String,
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
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

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

// Auth Routes - GitHub
app.get('/api/auth/github', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const url = ` https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${process.env.GITHUB_CALLBACK_URL}&scope=user:email&state=${state}`;
  res.json({ url, state });
});

app.post('/api/auth/github/callback', async (req, res) => {
  const { code, state } = req.body;
  
  try {
    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: process.env.GITHUB_CALLBACK_URL
    }, {
      headers: { Accept: 'application/json' },
      timeout: 10000  // 10秒超时
    });

    const accessToken = tokenResponse.data.access_token;

    // Get user info
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${accessToken}` },
      timeout: 10000  // 10秒超时
    });

    const userData = userResponse.data;

    // Find or create user
    let user = await User.findOne({ provider: 'github', providerId: userData.id });
    if (!user) {
      user = new User({
        username: userData.login,
        email: userData.email,
        avatar: userData.avatar_url,
        provider: 'github',
        providerId: userData.id
      });
      await user.save();
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user._id, username: user.username, avatar: user.avatar } });
  } catch (error) {
    console.error('GitHub auth error:', error.response?.data || error.message);
    console.error('Error details:', error);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// Similar for WeChat (WeChat OAuth is more complex, requires appid, secret, and proper configuration)
app.get('/api/auth/wechat', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const url = `https://open.weixin.qq.com/connect/oauth2/authorize?appid=${process.env.WECHAT_APP_ID}&redirect_uri=${encodeURIComponent(process.env.WECHAT_CALLBACK_URL)}&response_type=code&scope=snsapi_userinfo&state=${state}#wechat_redirect`;
  res.json({ url, state });
});

app.post('/api/auth/wechat/callback', async (req, res) => {
  const { code, state } = req.body;
  
  try {
    // Exchange code for access token
    const tokenResponse = await axios.get(`https://api.weixin.qq.com/sns/oauth2/access_token?appid=${process.env.WECHAT_APP_ID}&secret=${process.env.WECHAT_APP_SECRET}&code=${code}&grant_type=authorization_code`);

    const { access_token, openid } = tokenResponse.data;

    // Get user info
    const userResponse = await axios.get(`https://api.weixin.qq.com/sns/userinfo?access_token=${access_token}&openid=${openid}&lang=zh_CN`);

    const userData = userResponse.data;

    // Find or create user
    let user = await User.findOne({ provider: 'wechat', providerId: openid });
    if (!user) {
      user = new User({
        username: userData.nickname,
        avatar: userData.headimgurl,
        provider: 'wechat',
        providerId: openid
      });
      await user.save();
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user._id, username: user.username, avatar: user.avatar } });
  } catch (error) {
    console.error('WeChat auth error:', error);
    res.status(500).json({ error: 'Authentication failed' });
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
