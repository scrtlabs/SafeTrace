<script type="text/javascript">


function parsed_data() {
var apiData = {location_data:[]};
var d = new Date();
var current_time = d.getTime();
//only use data starting from 2 weeks ago
var begin_time = current_time - (2 * 604800 * 1000)

    fetch("http://localhost:8000/2020_JANUARY.json")
        .then(function (resp) {
            return resp.json();

        })
        .then(function (data) {
                data.timelineObjects.forEach(function (obj) {
                    if (Object.keys(obj) == 'placeVisit' && obj.placeVisit.duration.startTimestampMs > begin_time) {
                        var lat = obj.placeVisit.location.latitudeE7 / 10000000
                        var lng = obj.placeVisit.location.longitudeE7 / 10000000
                        var startTime = obj.placeVisit.duration.startTimestampMs
                        var endTime = obj.placeVisit.duration.endTimestampMs

                        apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime});



                    }
                });
            }
        )

return apiData;
}

parsed_data();

</script>


