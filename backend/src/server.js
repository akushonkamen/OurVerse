const app = require('./app');
const config = require('./config/env');
const { connectDatabase } = require('./config/database');
const { normaliseAllPhotoAssets } = require('./services/photo-storage-service');

const startServer = async () => {
  try {
    await connectDatabase();
    console.log('Connected to MongoDB');

    normaliseAllPhotoAssets()
      .then(result => {
        const { processed, migrated, updatedUrls, missing, error } = result;
        if (error) {
          console.warn('Photo asset normalisation encountered issues:', error);
        } else {
          console.log('Photo asset normalisation complete:', {
            processed,
            migrated,
            updatedUrls,
            missing
          });
        }
      })
      .catch(normaliseError => {
        console.warn('Photo asset normalisation failed:', normaliseError.message);
      });
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }

  if (config.flags.isRailway) {
    console.log('🚂 Running on Railway platform');
  }

  app.listen(config.port, config.host, () => {
    if (config.env === 'development') {
      console.log(`HTTP Server running on http://${config.host}:${config.port}`);
      console.log(`GitHub callback URL: ${config.getGitHubCallbackUrl()}`);
      console.log(`Access website at: http://localhost:${config.port}/website.html`);
    } else {
      console.log(`Server running on port ${config.port}`);
    }
  });
};

startServer();
