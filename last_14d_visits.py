# Converst Google Takeout Data to API endpoint format
# Only send data placevisits for the last 2 weeks

import ijson
import time
import json

import boto3


# In case we need to download off s3
#s3 = boto3.client('s3')
#s3.download_file('covid19-tracer', 'LocationHistory.json', 'location.json')
#print('file download complete')


current_milli_time = lambda: int(round(time.time() * 1000))

# Specify json file below
with open('2020_JANUARY.json','rb') as input_file:

    #up to 2 weeks ago
    begin_time = current_milli_time() - (2 * 604800 * 1000)

    # Collection placeVisits
    objects = ijson.items(input_file, 'timelineObjects.item.placeVisit')

    # Only keep those visits from the last 14 days
    placevisits = (o for o in objects if int(o['duration']['startTimestampMs']) > begin_time)

    with open('output_json.json', 'w') as output_file:
        output_data = []
        for visits in placevisits:
            row = {}
            row["lat"] = visits['location']['latitudeE7']
            row["lng"] = visits['location']['longitudeE7']
            row["startTS"] = int(visits['duration']['startTimestampMs'])
            row["endTS"] = int(visits['duration']['endTimestampMs'])

            output_data.append(row)
            print (output_data)

        json.dump(output_data, output_file, indent=4)

