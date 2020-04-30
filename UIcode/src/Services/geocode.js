const GEOCODE_URL = "https://maps.google.com/maps/api/geocode/json";
const API_KEY = process.env.REACT_APP_GOOGLE_MAPS_API_KEY;

const formatLatLng = (lat, lng) => {
  if (!lat || !lng) {
    throw new Error("Provided coordinates are invalid");
  }

  return encodeURIComponent(`${lat},${lng}`);
};

const makeRequest = async (url) => {
  const response = await fetch(url);
  const json = await response.json()

  if (json.status === "OK") {
    return json;
  }

  return new Error(
    `${json.error_message}.\nServer returned status code ${json.status}`
  );
};

export const fromLatLng = async (lat, lng) => {
  const latLng = formatLatLng(lat, lng);

  const url = `${GEOCODE_URL}?latlng=${latLng}&key=${API_KEY}`;

  return makeRequest(url);
};