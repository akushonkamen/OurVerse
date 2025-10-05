const multer = require('multer');
const config = require('../config/env');

const storage = multer.memoryStorage();

const getMimeWhitelist = () => {
  const defaultTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif'];
  const overrides = config.allowedFileTypesRaw
    .split(',')
    .map(type => type.trim())
    .filter(Boolean);
  return overrides.length ? overrides : defaultTypes;
};

const upload = multer({
  storage,
  limits: {
    fileSize: config.maxFileSize
  },
  fileFilter: (req, file, cb) => {
    const whitelist = getMimeWhitelist();
    if (whitelist.includes(file.mimetype)) {
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

module.exports = {
  uploadSinglePhoto
};
