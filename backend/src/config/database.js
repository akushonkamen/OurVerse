const mongoose = require('mongoose');
const config = require('./env');

const connectDatabase = async () => {
  await mongoose.connect(config.mongodbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
};

mongoose.connection.once('open', () => {
  console.log('MongoDB connected');
});

module.exports = {
  connectDatabase
};
