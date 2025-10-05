const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const config = require('./env');
const User = require('../models/user');

const applyPassportStrategies = () => {
  if (!config.github.clientId || !config.github.clientSecret) {
    console.warn('GitHub OAuth credentials are not fully configured; GitHub login will be unavailable.');
    return;
  }

  passport.use(new GitHubStrategy({
      clientID: config.github.clientId,
      clientSecret: config.github.clientSecret,
      callbackURL: config.getGitHubCallbackUrl(),
      scope: ['user:email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('GitHub profile:', {
          id: profile.id,
          username: profile.username,
          emails: profile.emails,
          photos: profile.photos
        });

        let user = await User.findOne({ githubId: profile.id });

        if (user) {
          user.githubUsername = profile.username;
          if (profile.photos && profile.photos[0]) {
            user.avatar = profile.photos[0].value;
          }
          await user.save();
          return done(null, user);
        }

        const email = (profile.emails && profile.emails[0])
          ? profile.emails[0].value
          : `${profile.username}@github.local`;

        const avatar = (profile.photos && profile.photos[0])
          ? profile.photos[0].value
          : `https://api.dicebear.com/7.x/avataaars/svg?seed=${profile.username}`;

        user = new User({
          username: profile.username,
          email,
          avatar,
          provider: 'github',
          githubId: profile.id,
          githubUsername: profile.username
        });

        await user.save();
        console.log('Created new GitHub user:', user.username);
        return done(null, user);
      } catch (error) {
        console.error('GitHub strategy error:', error);
        return done(error, null);
      }
    }
  ));
};

module.exports = {
  passport,
  applyPassportStrategies
};
