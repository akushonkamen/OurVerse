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

  const usersCollection = mongoose.connection.db.collection('users');

  try {
    const cleanupResult = await usersCollection.updateMany(
      { $or: [{ email: null }, { email: '' }] },
      { $unset: { email: '' } }
    );
    if (cleanupResult.modifiedCount) {
      console.log(`Normalised ${cleanupResult.modifiedCount} user email field(s)`);
    }
  } catch (error) {
    console.warn('Failed to normalise email fields:', error.message);
  }

  try {
    await usersCollection.dropIndex('registrationDeviceId_1');
    console.log('Dropped legacy registrationDeviceId index');
  } catch (error) {
    if (!['IndexNotFound', 'IndexBuildInProgress'].includes(error?.codeName)) {
      console.warn('Failed to drop legacy registrationDeviceId index:', error.message);
    }
  }

  try {
    await usersCollection.createIndex(
      { registrationDeviceId: 1 },
      { name: 'registrationDeviceId_1', sparse: true, background: true }
    );
    console.log('Ensured non-unique registrationDeviceId index');
  } catch (error) {
    if (error?.codeName === 'IndexBuildInProgress') {
      console.warn('registrationDeviceId index build already in progress, skipping');
    } else {
      console.warn('Failed to ensure registrationDeviceId index:', error.message);
    }
  }

  try {
    await usersCollection.dropIndex('email_1');
    console.log('Dropped legacy email index');
  } catch (error) {
    if (!['IndexNotFound', 'IndexBuildInProgress'].includes(error?.codeName)) {
      console.warn('Failed to drop legacy email index:', error.message);
    }
  }

  try {
    await usersCollection.createIndex(
      { email: 1 },
      {
        name: 'email_1',
        unique: true,
        background: true,
        partialFilterExpression: {
          email: { $exists: true, $type: 'string' }
        }
      }
    );
    console.log('Ensured partial unique email index');
  } catch (error) {
    if (error?.codeName === 'IndexBuildInProgress') {
      console.warn('Email index build already in progress, skipping');
    } else {
      console.warn('Failed to ensure email index:', error.message);
    }
  }
});

module.exports = {
  connectDatabase
};
