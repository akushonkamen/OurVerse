const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const earthRadiusKm = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
    + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180)
    * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return earthRadiusKm * c * 1000;
};

const parseAmapRectangle = rectangle => {
  if (!rectangle) {
    return null;
  }

  const [southwestRaw, northeastRaw] = rectangle.split(';');
  if (!southwestRaw || !northeastRaw) {
    return null;
  }

  const [lng1, lat1] = southwestRaw.split(',').map(Number);
  const [lng2, lat2] = northeastRaw.split(',').map(Number);

  if (![lng1, lat1, lng2, lat2].every(Number.isFinite)) {
    return null;
  }

  const centerLng = (lng1 + lng2) / 2;
  const centerLat = (lat1 + lat2) / 2;

  return {
    centerLat,
    centerLng,
    southwest: { lat: Math.min(lat1, lat2), lng: Math.min(lng1, lng2) },
    northeast: { lat: Math.max(lat1, lat2), lng: Math.max(lng1, lng2) }
  };
};

module.exports = {
  calculateDistance,
  parseAmapRectangle
};
