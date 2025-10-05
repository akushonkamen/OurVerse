const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const exifParser = require('exif-parser');
const jwt = require('jsonwebtoken');
const Photo = require('../models/photo');
const User = require('../models/user');
const config = require('../config/env');
const { calculateDistance } = require('../utils/geo-utils');
const { buildPhotoLocationInfo } = require('../services/amap-service');
const {
  ensurePhotoDocumentAsset,
  ensurePhotoRecordAsset,
  resolvePhotoFilePath,
  pruneEmptyParentDirs,
  fileExists
} = require('../services/photo-storage-service');

const uploadsRoot = path.resolve(__dirname, '..', '..', config.uploadsDir);

const ensureUploadsDir = async () => {
  await fs.promises.mkdir(uploadsRoot, { recursive: true });
};

const getViewerIdFromRequest = req => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    return null;
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    return decoded?.userId ? String(decoded.userId) : null;
  } catch (error) {
    if (config.env !== 'production') {
      console.warn('Failed to decode viewer token for photo details:', error.message);
    }
    return null;
  }
};


const uploadPhoto = async (req, res) => {
  try {
    const { caption, userLat, userLng, locationSource } = req.body;
    const file = req.file;

    if (req.fileValidationError) {
      return res.status(400).json({ error: req.fileValidationError });
    }

    if (!file) {
      return res.status(400).json({ error: 'No photo provided' });
    }

    if (!caption) {
      return res.status(400).json({ error: 'Caption required' });
    }

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

    if (todayUploads >= config.dailyUploadLimit) {
      return res.status(400).json({ error: `每日最多只能上传${config.dailyUploadLimit}张照片，请明天再来` });
    }

    let exif = { tags: {} };
    try {
      exif = exifParser.create(file.buffer).parse();
    } catch (parseError) {
      console.warn('EXIF解析失败，将视为无GPS信息:', parseError.message);
    }

    const gps = exif.tags || {};
    const hasExifCoords = Number.isFinite(gps.GPSLatitude) && Number.isFinite(gps.GPSLongitude);

    const parsedUserLat = Number(userLat);
    const parsedUserLng = Number(userLng);
    const hasUserCoords = Number.isFinite(parsedUserLat) && Number.isFinite(parsedUserLng);

    let photoLat;
    let photoLng;
    let distanceToUser = 0;

    if (hasExifCoords) {
      photoLat = Number(gps.GPSLatitude);
      photoLng = Number(gps.GPSLongitude);
      if (gps.GPSLatitudeRef === 'S') {
        photoLat = -photoLat;
      }
      if (gps.GPSLongitudeRef === 'W') {
        photoLng = -photoLng;
      }

      if (!hasUserCoords) {
        return res.status(400).json({ error: '缺少当前位置坐标，无法验证照片位置' });
      }

      distanceToUser = calculateDistance(parsedUserLat, parsedUserLng, photoLat, photoLng);
      if (distanceToUser > config.maxDistanceVerification) {
        return res.status(400).json({ error: `照片拍摄位置与您当前所在位置相距过远 (${Math.round(distanceToUser)}米)，请确认您在照片拍摄地点附近` });
      }
    } else if (locationSource === 'gps' || locationSource === 'amap') {
      if (!hasUserCoords) {
        return res.status(400).json({ error: '缺少当前位置坐标，无法记录照片位置' });
      }
      photoLat = parsedUserLat;
      photoLng = parsedUserLng;
      distanceToUser = 0;
    } else {
      return res.status(400).json({ error: '为了确保照片真实性，请使用GPS定位后再上传照片，或选择包含位置信息的照片' });
    }

    if (!Number.isFinite(photoLat) || !Number.isFinite(photoLng)) {
      return res.status(400).json({ error: '无法识别照片的地理位置信息' });
    }

    await ensureUploadsDir();

    const userIdString = String(req.userId);
    const now = new Date();
    const yearSegment = String(now.getUTCFullYear());
    const monthSegment = String(now.getUTCMonth() + 1).padStart(2, '0');

    const relativeDir = path.join(config.uploadsDir, userIdString, yearSegment, monthSegment);
    const absoluteDir = path.resolve(__dirname, '..', '..', relativeDir);
    await fs.promises.mkdir(absoluteDir, { recursive: true });

    const filename = `${crypto.randomBytes(16).toString('hex')}.jpg`;
    const filepath = path.join(absoluteDir, filename);

    await sharp(file.buffer)
      .resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toFile(filepath);

    const normalizedUploadsDir = config.uploadsDir.replace(/\\/g, '/');
    const baseSegments = normalizedUploadsDir.split('/').filter(Boolean);
    const urlSegments = [...baseSegments, userIdString, yearSegment, monthSegment, filename];
    const imageUrl = '/' + path.posix.join(...urlSegments);

    // Snap to existing photo location within ~10m to keep map markers clustered
    const CLUSTER_RADIUS_METERS = 10;
    let clusterAnchor;
    try {
      clusterAnchor = await Photo.findOne({
        location: {
          $near: {
            $geometry: { type: 'Point', coordinates: [photoLng, photoLat] },
            $maxDistance: CLUSTER_RADIUS_METERS
          }
        }
      }).select({ location: 1, locationInfo: 1 }).lean();
    } catch (clusterError) {
      console.warn('Nearby photo lookup for clustering failed:', clusterError.message);
    }

    if (clusterAnchor?.location?.coordinates?.length === 2) {
      const [clusterLng, clusterLat] = clusterAnchor.location.coordinates;
      photoLat = clusterLat;
      photoLng = clusterLng;
      if (hasUserCoords) {
        distanceToUser = calculateDistance(parsedUserLat, parsedUserLng, photoLat, photoLng);
      }
    }

    const locationInfo = clusterAnchor?.locationInfo
      ? clusterAnchor.locationInfo
      : await buildPhotoLocationInfo(photoLat, photoLng);

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
      exifLat: hasExifCoords ? photoLat : null,
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
};

const getNearbyPhotos = async (req, res) => {
  try {
    const { lat, lng, radius = 300 } = req.query;
    const userLat = Number(lat);
    const userLng = Number(lng);
    const searchRadius = Math.max(0, Number(radius) || 0) || 300;

    if (!Number.isFinite(userLat) || !Number.isFinite(userLng)) {
      return res.status(400).json({ error: '缺少或无效的当前位置坐标' });
    }

    const viewerId = getViewerIdFromRequest(req);

    const nearbyPhotosRaw = await Photo.aggregate([
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
          userId: '$userId',
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

    const nearbyPhotos = [];

    for (const photo of nearbyPhotosRaw) {
      const normalizedUrl = await ensurePhotoRecordAsset(photo);
      const ownerId = photo.userId ? String(photo.userId) : null;
      const assetPath = resolvePhotoFilePath(normalizedUrl || photo.url);
      const assetExists = await fileExists(assetPath);

      if (!assetExists) {
        continue;
      }

      nearbyPhotos.push({
        id: String(photo.id),
        userId: ownerId,
        url: normalizedUrl || photo.url,
        caption: photo.caption,
        lat: photo.lat,
        lng: photo.lng,
        locationInfo: photo.locationInfo,
        distance: photo.distance,
        comments: photo.comments,
        username: photo.username,
        userAvatar: photo.userAvatar,
        createdAt: photo.createdAt,
        canDelete: Boolean(viewerId && ownerId && viewerId === ownerId)
      });
    }

    res.json({ photos: nearbyPhotos });
  } catch (error) {
    console.error('Nearby photos error:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
};

const getMyPhotos = async (req, res) => {
  try {
    const userId = req.userId;
    const { page = 1, limit = 20 } = req.query;

    const numericLimit = Number.parseInt(limit, 10) || 20;
    const numericPage = Number.parseInt(page, 10) || 1;

    const photos = await Photo.find({ userId })
      .sort({ createdAt: -1 })
      .limit(numericLimit)
      .skip((numericPage - 1) * numericLimit)
      .populate('userId', 'username avatar');

    const filteredPhotos = [];
    let missingAssets = 0;

    for (const photo of photos) {
      await ensurePhotoDocumentAsset(photo);
      const assetPath = resolvePhotoFilePath(photo.url);
      const assetExists = await fileExists(assetPath);

      if (!assetExists) {
        missingAssets += 1;
        continue;
      }

      filteredPhotos.push(photo);
    }

    const total = await Photo.countDocuments({ userId });

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      photos: filteredPhotos.map(photo => ({
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
        createdAt: photo.createdAt,
        canDelete: true
      })),
      pagination: {
        page: numericPage,
        limit: numericLimit,
        total,
        pages: Math.ceil(total / numericLimit),
        returned: filteredPhotos.length
      },
      stats: {
        missingAssetsInPage: missingAssets
      }
    });
  } catch (error) {
    console.error('My photos error:', error);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
};

const getPhotoDetails = async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id)
      .populate('userId', 'username avatar')
      .populate('comments.userId', 'username avatar');

    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    await ensurePhotoDocumentAsset(photo);
    const assetPath = resolvePhotoFilePath(photo.url);
    const assetExists = await fileExists(assetPath);

    if (!assetExists) {
      return res.status(404).json({ error: '照片源文件已丢失' });
    }

    const ownerId = photo.userId?._id
      ? String(photo.userId._id)
      : photo.userId?.toString?.() || null;
    const viewerId = req.userId ? String(req.userId) : getViewerIdFromRequest(req);
    const canDelete = Boolean(viewerId && ownerId && viewerId === ownerId);

    res.json({
      photo: {
        id: photo._id,
        url: photo.url,
        caption: photo.caption,
        lat: photo.lat,
        lng: photo.lng,
        locationInfo: photo.locationInfo,
        user: {
          id: ownerId,
          username: photo.userId.username,
          avatar: photo.userId.avatar
        },
        createdAt: photo.createdAt,
        canDelete,
        comments: photo.comments.map(comment => {
          const commentUser = comment.userId && typeof comment.userId === 'object' && 'username' in comment.userId
            ? comment.userId
            : null;
          return {
            username: commentUser?.username || comment.username,
            avatar: commentUser?.avatar || '',
            text: comment.text,
            createdAt: comment.createdAt
          };
        })
      }
    });
  } catch (error) {
    console.error('Get photo details error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const addPhotoComment = async (req, res) => {
  try {
    const { comment } = req.body;

    if (!comment) {
      return res.status(400).json({ error: 'Comment required' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const photo = await Photo.findById(req.params.id);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

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
    console.error('Add photo comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const deletePhoto = async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: 'Photo id is required' });
    }

    const photo = await Photo.findById(id);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    const ownerId = photo.userId?.toString?.() || null;
    if (!ownerId) {
      console.warn('Attempted to delete photo with missing owner:', id);
      return res.status(400).json({ error: '照片缺少归属信息，无法删除' });
    }

    if (String(req.userId) !== ownerId) {
      return res.status(403).json({ error: '无权删除这张照片' });
    }

    const filePath = resolvePhotoFilePath(photo.url);

    await photo.deleteOne();

    if (filePath) {
      try {
        await fs.promises.unlink(filePath);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          console.warn('Failed to delete photo file:', {
            filePath,
            message: error.message
          });
        }
      }

      await pruneEmptyParentDirs(filePath, ownerId);
    }

    res.json({ success: true, id });
  } catch (error) {
    console.error('Delete photo error:', error);
    res.status(500).json({ error: 'Failed to delete photo' });
  }
};

module.exports = {
  uploadPhoto,
  getNearbyPhotos,
  getMyPhotos,
  getPhotoDetails,
  addPhotoComment,
  deletePhoto
};
