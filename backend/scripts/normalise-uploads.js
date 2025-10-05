#!/usr/bin/env node

const mongoose = require('mongoose');
const { connectDatabase } = require('../src/config/database');
const { normaliseAllPhotoAssets } = require('../src/services/photo-storage-service');

const run = async () => {
  try {
    await connectDatabase();
    const result = await normaliseAllPhotoAssets();
    console.log('Photo asset normalisation finished:', result);
  } catch (error) {
    console.error('Failed to normalise photo assets:', error);
    process.exitCode = 1;
  } finally {
    await mongoose.connection.close().catch(() => {});
  }
};

run();
