const fs = require('fs');
const path = require('path');
const Photo = require('../models/photo');
const config = require('../config/env');

const UPLOADS_ROOT = path.resolve(__dirname, '..', '..', config.uploadsDir);

const uploadsDirPosix = (config.uploadsDir || 'uploads')
  .replace(/\\/g, '/')
  .replace(/^\/+/, '')
  .replace(/\/+$/, '') || 'uploads';

const ensureDirectory = async dirPath => {
  if (!dirPath) {
    return;
  }

  await fs.promises.mkdir(dirPath, { recursive: true });
};

const fileExists = async filePath => {
  if (!filePath) {
    return false;
  }
  try {
    await fs.promises.access(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
};

const resolvePhotoFilePath = photoUrl => {
  if (!photoUrl) {
    return null;
  }

  const sanitized = photoUrl.split('?')[0].replace(/\\/g, '/');
  const trimmed = sanitized.startsWith('/') ? sanitized.slice(1) : sanitized;
  const absolutePath = path.resolve(__dirname, '..', '..', trimmed);
  const relativeToRoot = path.relative(UPLOADS_ROOT, absolutePath);

  if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
    return null;
  }

  return absolutePath;
};

const pruneEmptyParentDirs = async (filePath, ownerId) => {
  if (!filePath || !ownerId) {
    return;
  }

  const ownerUploadsRoot = path.resolve(UPLOADS_ROOT, String(ownerId));
  let currentDir = path.dirname(filePath);

  while (currentDir.startsWith(ownerUploadsRoot) && currentDir !== ownerUploadsRoot) {
    try {
      const entries = await fs.promises.readdir(currentDir);
      if (entries.length > 0) {
        break;
      }
      await fs.promises.rm(currentDir, { recursive: false, force: true });
      currentDir = path.dirname(currentDir);
    } catch (error) {
      if (error.code === 'ENOENT') {
        currentDir = path.dirname(currentDir);
        continue;
      }

      console.warn('Directory cleanup skipped:', {
        directory: currentDir,
        message: error.message
      });
      break;
    }
  }

  try {
    const ownerEntries = await fs.promises.readdir(ownerUploadsRoot);
    if (!ownerEntries.length) {
      await fs.promises.rm(ownerUploadsRoot, { recursive: false, force: true });
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.warn('Failed to prune user upload root:', {
        directory: ownerUploadsRoot,
        message: error.message
      });
    }
  }
};

const buildExpectedRelativePath = (ownerId, createdAt, filename) => {
  const safeOwner = String(ownerId);
  const baseDate = createdAt instanceof Date ? createdAt : new Date(createdAt || Date.now());
  const yearSegment = String(baseDate.getUTCFullYear());
  const monthSegment = String(baseDate.getUTCMonth() + 1).padStart(2, '0');

  return path.posix.join(uploadsDirPosix, safeOwner, yearSegment, monthSegment, filename);
};

const ensurePhotoAssetPlacement = async ({
  ownerId,
  currentUrl,
  createdAt,
  onUrlUpdated,
  photoId
}) => {
  if (!ownerId || !currentUrl) {
    return currentUrl;
  }

  const sanitized = currentUrl.split('?')[0].replace(/\\/g, '/');
  const relativeFromUrl = sanitized.startsWith('/') ? sanitized.slice(1) : sanitized;
  const absoluteFromUrl = relativeFromUrl
    ? path.resolve(__dirname, '..', '..', relativeFromUrl)
    : null;

  const filename = path.posix.basename(relativeFromUrl || currentUrl);
  if (!filename) {
    return currentUrl;
  }

  const expectedRelativePath = buildExpectedRelativePath(ownerId, createdAt, filename);
  const expectedAbsolutePath = path.resolve(__dirname, '..', '..', expectedRelativePath);
  const expectedUrl = '/' + expectedRelativePath;

  if (await fileExists(absoluteFromUrl)) {
    if (relativeFromUrl !== expectedRelativePath) {
      try {
        await ensureDirectory(path.dirname(expectedAbsolutePath));
        await fs.promises.rename(absoluteFromUrl, expectedAbsolutePath);
        if (typeof onUrlUpdated === 'function') {
          await onUrlUpdated(expectedUrl);
        }
        return expectedUrl;
      } catch (error) {
        console.warn('Failed to relocate legacy photo file:', {
          photoId,
          from: absoluteFromUrl,
          to: expectedAbsolutePath,
          message: error.message
        });
      }
    }
    return currentUrl;
  }

  if (await fileExists(expectedAbsolutePath)) {
    if (relativeFromUrl !== expectedRelativePath && typeof onUrlUpdated === 'function') {
      await onUrlUpdated(expectedUrl);
    }
    return expectedUrl;
  }

  const legacyAbsolutePath = path.resolve(UPLOADS_ROOT, path.basename(filename));
  if (await fileExists(legacyAbsolutePath)) {
    try {
      await ensureDirectory(path.dirname(expectedAbsolutePath));
      await fs.promises.rename(legacyAbsolutePath, expectedAbsolutePath);
      if (typeof onUrlUpdated === 'function') {
        await onUrlUpdated(expectedUrl);
      }
      return expectedUrl;
    } catch (error) {
      console.warn('Failed to migrate legacy photo file:', {
        photoId,
        from: legacyAbsolutePath,
        to: expectedAbsolutePath,
        message: error.message
      });
    }
  }

  return currentUrl;
};

const ensurePhotoDocumentAsset = async photoDoc => {
  if (!photoDoc) {
    return;
  }

  const ownerId = photoDoc.userId?._id
    ? String(photoDoc.userId._id)
    : photoDoc.userId?.toString?.();

  if (!ownerId) {
    return;
  }

  const updatedUrl = await ensurePhotoAssetPlacement({
    ownerId,
    currentUrl: photoDoc.url,
    createdAt: photoDoc.createdAt,
    photoId: photoDoc._id,
    onUrlUpdated: async newUrl => {
      if (photoDoc.url !== newUrl) {
        photoDoc.url = newUrl;
        try {
          await photoDoc.save();
        } catch (error) {
          console.warn('Failed to persist normalized photo url:', {
            photoId: photoDoc._id,
            message: error.message
          });
        }
      }
    }
  });

  if (updatedUrl && photoDoc.url !== updatedUrl) {
    photoDoc.url = updatedUrl;
  }
};

const ensurePhotoRecordAsset = async photoRecord => {
  if (!photoRecord || !photoRecord.userId) {
    return photoRecord?.url;
  }

  const ownerId = String(photoRecord.userId);
  const updatedUrl = await ensurePhotoAssetPlacement({
    ownerId,
    currentUrl: photoRecord.url,
    createdAt: photoRecord.createdAt,
    photoId: photoRecord.id,
    onUrlUpdated: async newUrl => {
      try {
        await Photo.findByIdAndUpdate(photoRecord.id, { url: newUrl });
      } catch (error) {
        console.warn('Failed to persist normalized photo url for record:', {
          photoId: photoRecord.id,
          message: error.message
        });
      }
    }
  });

  return updatedUrl || photoRecord.url;
};

const normaliseAllPhotoAssets = async () => {
  const result = {
    processed: 0,
    migrated: 0,
    updatedUrls: 0,
    missing: 0
  };

  try {
    const cursor = Photo.find({}).cursor();

    for await (const photo of cursor) {
      result.processed += 1;
      const beforeUrl = photo.url;
      const beforePath = resolvePhotoFilePath(beforeUrl);
      const existedBefore = await fileExists(beforePath);

      await ensurePhotoDocumentAsset(photo);

      const afterPath = resolvePhotoFilePath(photo.url);
      const existsAfter = await fileExists(afterPath);

      if (photo.url !== beforeUrl) {
        result.updatedUrls += 1;
      }

      if (existedBefore && existsAfter && beforePath !== afterPath) {
        result.migrated += 1;
      }

      if (!existsAfter) {
        result.missing += 1;
      }
    }
  } catch (error) {
    console.error('Photo asset normalisation failed:', error);
    result.error = error.message;
  }

  return result;
};

module.exports = {
  ensurePhotoDocumentAsset,
  ensurePhotoRecordAsset,
  resolvePhotoFilePath,
  pruneEmptyParentDirs,
  normaliseAllPhotoAssets,
  fileExists
};
