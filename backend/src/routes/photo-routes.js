const express = require('express');
const authenticate = require('../middlewares/authenticate');
const { uploadSinglePhoto } = require('../middlewares/upload');
const {
  uploadPhoto,
  getNearbyPhotos,
  getMyPhotos,
  getPhotoDetails,
  addPhotoComment,
  deletePhoto
} = require('../controllers/photo-controller');

const router = express.Router();

router.post('/upload', authenticate, uploadSinglePhoto, uploadPhoto);
router.get('/nearby', getNearbyPhotos);
router.get('/my', authenticate, getMyPhotos);
router.delete('/:id', authenticate, deletePhoto);
router.get('/:id', getPhotoDetails);
router.post('/:id/comments', authenticate, addPhotoComment);

module.exports = router;
