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

const parseByteSize = (value, fallback) => {
  if (value === undefined || value === null) {
    return fallback;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  const raw = String(value).trim();
  if (!raw.length) {
    return fallback;
  }

  const match = raw.match(/^(\d+(?:\.\d+)?)(b|kb|k|mb|m|gb|g)?$/i);
  if (!match) {
    return fallback;
  }

  const numeric = Number.parseFloat(match[1]);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }

  const unit = (match[2] || 'b').toLowerCase();
  const multipliers = {
    b: 1,
    k: 1024,
    kb: 1024,
    m: 1024 * 1024,
    mb: 1024 * 1024,
    g: 1024 * 1024 * 1024,
    gb: 1024 * 1024 * 1024
  };

  const multiplier = multipliers[unit];
  if (!multiplier) {
    return fallback;
  }

  return Math.round(numeric * multiplier);
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
  maxFileSize: parseByteSize(process.env.MAX_FILE_SIZE, 100 * 1024 * 1024),
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

const pickFirstHeaderValue = value => {
  if (!value) {
    return null;
  }
  if (Array.isArray(value)) {
    return value[0];
  }
  return String(value).split(',')[0].trim();
};

const normaliseBaseUrl = value => (value ? value.replace(/\/+$/, '') : value);

const stripPort = host => {
  if (!host) {
    return host;
  }
  const [hostname] = host.split(':');
  return hostname.toLowerCase();
};

const getUrlHost = value => {
  if (!value) {
    return null;
  }
  try {
    return new URL(value).host;
  } catch (error) {
    return null;
  }
};

const getRequestHost = req => {
  if (!req) {
    return null;
  }
  const forwarded = pickFirstHeaderValue(req.headers?.['x-forwarded-host']);
  return forwarded || pickFirstHeaderValue(req.headers?.host);
};

const getRequestProtocol = req => {
  if (!req) {
    return null;
  }
  const forwarded = pickFirstHeaderValue(req.headers?.['x-forwarded-proto']);
  if (forwarded) {
    return forwarded;
  }
  if (typeof req.protocol === 'string' && req.protocol.length) {
    return req.protocol;
  }
  if (req.secure === true) {
    return 'https';
  }
  return null;
};

const isLocalHost = host => {
  if (!host) {
    return false;
  }
  const normalised = stripPort(host);
  return normalised === 'localhost' || normalised === '127.0.0.1';
};

config.getGitHubCallbackUrl = req => {
  const requestHost = getRequestHost(req);
  const requestProtocol = getRequestProtocol(req) || config.protocol || 'https';
  const envCallback = normaliseBaseUrl(config.github.callbackUrl);
  const envCallbackHost = getUrlHost(envCallback);

  if (requestHost && !isLocalHost(requestHost)) {
    if (envCallbackHost && stripPort(envCallbackHost) === stripPort(requestHost)) {
      return envCallback;
    }
    return `${requestProtocol}://${requestHost}/api/auth/github/callback`;
  }

  if (envCallback) {
    return envCallback;
  }

  if (config.env === 'development') {
    return `http://localhost:${config.port}/api/auth/github/callback`;
  }

  return `${config.protocol}://${config.domain}/api/auth/github/callback`;
};

config.getFrontendBaseUrl = req => {
  const requestHost = getRequestHost(req);
  const requestProtocol = getRequestProtocol(req) || config.protocol || 'https';
  const envFrontend = normaliseBaseUrl(config.frontendUrl);
  const envFrontendHost = getUrlHost(envFrontend);

  if (requestHost && !isLocalHost(requestHost)) {
    if (envFrontendHost && stripPort(envFrontendHost) === stripPort(requestHost)) {
      return envFrontend;
    }
    return normaliseBaseUrl(`${requestProtocol}://${requestHost}`);
  }

  if (envFrontend) {
    return envFrontend;
  }

  if (config.env === 'development') {
    return `http://localhost:${config.port}`;
  }

  return `${config.protocol}://${config.domain}`;
};

module.exports = config;
