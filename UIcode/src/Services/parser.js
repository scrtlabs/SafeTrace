export const parseJsonFile = async (file) => {
  const reader = new FileReader();

  return new Promise((resolve, reject) => {
    reader.onload = (evt) => {
      let parsed;
      try {
        parsed = JSON.parse(evt.target.result);
      } catch {
        return reject(new Error("Invalid file"));
      }

      if (
        parsed.hasOwnProperty("timelineObjects") &&
        Array.isArray(parsed.timelineObjects)
      ) {
        return resolve(parsed);
      } else {
        return reject(new Error("Invalid file"));
      }
    };
    reader.readAsText(file);
  });
};

export const isPlaceVisitActivity = (location) =>
  location.hasOwnProperty("placeVisit");

export const startedAfter = (timestamp) => (location) =>
  location.placeVisit.duration.startTimestampMs > timestamp;

export const activityTransformer = (testResult) => (activity) => ({
  lat: activity.placeVisit.location.latitudeE7 / 10000000,
  lng: activity.placeVisit.location.longitudeE7 / 10000000,
  startTS: activity.placeVisit.duration.startTimestampMs / 1,
  endTS: activity.placeVisit.duration.endTimestampMs / 1,
  testResult,
});

export const convertLocationData = (json, testResult = false) => {
  const startingDate = new Date().getTime() - 2 * 604800 * 1000;

  const activityFilter = (activity) =>
    isPlaceVisitActivity(activity) && startedAfter(startingDate)(activity);
  console.log('json_convertelocationata',json);
  return json.timelineObjects
    .filter(activityFilter)
    .map(activityTransformer(testResult));
};
