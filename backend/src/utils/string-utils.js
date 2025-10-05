const normaliseOrigin = origin => {
  if (!origin) {
    return '';
  }

  try {
    const url = new URL(origin);
    return `${url.protocol}//${url.host}`;
  } catch {
    return origin.trim();
  }
};

const toCleanString = value => {
  if (Array.isArray(value)) {
    const candidate = value.find(item => item != null && item !== '') ?? value[0];
    return candidate != null ? toCleanString(candidate) : '';
  }

  if (value == null) {
    return '';
  }

  return typeof value === 'string' ? value : String(value);
};

module.exports = {
  normaliseOrigin,
  toCleanString
};
