const express = require('express');
const authenticate = require('../middlewares/authenticate');
const optionalAuth = require('../middlewares/optional-auth');
const { uploadSinglePhoto } = require('../middlewares/upload');
const {
  uploadPhoto,
  getNearbyPhotos,
  getMyPhotos,
  getPhotoDetails,
  addPhotoComment,
  deletePhoto,
  uploadAnonymousPhoto,
  deleteAnonymousPhoto,
  getAnonymousMyPhotos
} = require('../controllers/photo-controller');

const router = express.Router();

router.post('/upload', authenticate, uploadSinglePhoto, uploadPhoto);
router.get('/nearby', getNearbyPhotos);
router.get('/my', authenticate, getMyPhotos);
router.post('/anonymous', optionalAuth, uploadSinglePhoto, uploadAnonymousPhoto);
router.delete('/anonymous/:id', optionalAuth, deleteAnonymousPhoto);
router.get('/anonymous/my', optionalAuth, getAnonymousMyPhotos);
router.delete('/:id', authenticate, deletePhoto);
router.get('/:id', getPhotoDetails);
router.post('/:id/comments', authenticate, addPhotoComment);

module.exports = router;
