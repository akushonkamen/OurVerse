const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

const envCandidates = [
  path.resolve(__dirname, '..', '..', '.env'),
  path.resolve(__dirname, '..', '.env')
];

for (const candidate of envCandidates) {
  if (fs.existsSync(candidate)) {
    dotenv.config({ path: candidate });
    break;
  }
}

const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(name => !process.env[name]);
if (missingEnvVars.length) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

const sessionSecret = process.env.SESSION_SECRET || process.env.JWT_SECRET;
if (!sessionSecret) {
  console.error('SESSION_SECRET or JWT_SECRET must be defined for session management');
  process.exit(1);
}

const parseInteger = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const config = {
  env: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
  port: parseInteger(process.env.PORT, 8444),
  host: process.env.HOST || '0.0.0.0',
  mongodbUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret,
  uploadsDir: process.env.UPLOADS_DIR || 'uploads',
  allowedOriginsRaw: (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || ''),
  allowedFileTypesRaw: process.env.ALLOWED_FILE_TYPES || '',
  maxFileSize: parseInteger(process.env.MAX_FILE_SIZE, 10 * 1024 * 1024),
  sessionCookieMaxAge: parseInteger(process.env.SESSION_COOKIE_MAX_AGE, 24 * 60 * 60 * 1000),
  rateLimit: {
    windowMs: parseInteger(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    maxRequests: parseInteger(process.env.RATE_LIMIT_MAX_REQUESTS, 100)
  },
  dailyUploadLimit: parseInteger(process.env.DAILY_UPLOAD_LIMIT, 5),
  maxDistanceVerification: parseInteger(process.env.MAX_DISTANCE_VERIFICATION, 50),
  bcryptSaltRounds: parseInteger(process.env.BCRYPT_SALT_ROUNDS, 10),
  protocol: process.env.PROTOCOL || 'https',
  domain: process.env.DOMAIN || 'localhost',
  frontendUrl: process.env.FRONTEND_URL || '',
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackUrl: process.env.GITHUB_CALLBACK_URL,
    token: process.env.GITHUB_TOKEN
  },
  amap: {
    webApiKey: process.env.AMAP_WEB_API_KEY,
    restApiKey: process.env.AMAP_REST_API_KEY,
    securityCode: process.env.AMAP_SECURITY_CODE
  },
  flags: {
    isRailway: Boolean(process.env.RAILWAY)
  }
};

config.getGitHubCallbackUrl = () => {
  if (config.env === 'development') {
    return `http://localhost:${config.port}/api/auth/github/callback`;
  }
  return config.github.callbackUrl || `${config.protocol}://${config.domain}/api/auth/github/callback`;
};

config.getFrontendBaseUrl = () => {
  if (config.frontendUrl) {
    return config.frontendUrl;
  }

  if (config.env === 'development') {
    return `http://localhost:${config.port}`;
  }

  return `${config.protocol}://${config.domain}`;
};

module.exports = config;
