const mongoose = require('mongoose');
const config = require('./env');

const connectDatabase = async () => {
  await mongoose.connect(config.mongodbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
};

mongoose.connection.once('open', async () => {
  try {
    await mongoose.connection.db.collection('users').dropIndex('githubId_1');
    console.log('Dropped legacy githubId index');
  } catch (error) {
    if (error?.codeName !== 'IndexNotFound') {
      console.warn('Failed to drop legacy githubId index:', error.message);
    }
  }

  try {
    await mongoose.connection.db.collection('users').dropIndex('registrationDeviceId_1');
    console.log('Dropped legacy registrationDeviceId index');
  } catch (error) {
    if (error?.codeName !== 'IndexNotFound') {
      console.warn('Failed to drop legacy registrationDeviceId index:', error.message);
    }
  }
});

module.exports = {
  connectDatabase
};
