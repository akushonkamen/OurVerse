const express = require('express');
const authenticate = require('../middlewares/authenticate');
const {
  register,
  login,
  verifyToken,
  beginGitHubAuth,
  handleGitHubCallback
} = require('../controllers/auth-controller');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/verify', authenticate, verifyToken);
router.get('/github', beginGitHubAuth);
router.get('/github/callback', handleGitHubCallback);

module.exports = router;
