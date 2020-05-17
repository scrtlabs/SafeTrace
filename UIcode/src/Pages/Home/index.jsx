import React from "react";
import { Card, Button, CardColumns, CardGroup,  } from "react-bootstrap";
import styled from "styled-components";

const cardStyelGral = {
  paddding:"50px"};

const cardPicture = {
  width : "500px"
};

const cardTitle = {
  "font-style": "normal",
  "font-weight": "bold",
  "font-size": "38px",
  "line-height": "54px",
};

class Home extends React.Component {
  render() {
    return (
      <div>
        <div>
          <Card  style={{ width: "50%" }}>
            <Card.Body style={cardStyelGral}>
              <Card.Title style={cardTitle}>
                Yours privacy matters.Help to Combat COVID-19 safely and
                securely
              </Card.Title>
              <Card.Text>
                Privately share your location history and compare it with other
                anonymous users
              </Card.Text>
              <Button variant="primary">I want to help</Button>
            </Card.Body>
          </Card>
          <Card border="light">
            <Card.Body>
              <Card.Title>
                How it works
              </Card.Title>
              <CardGroup>
                <Card style={cardStyelGral}>
                  <Card.Title>Individual Reporting</Card.Title>
                  <Card.Text>
                  See the times and the locations where you had high risk interactions so that users may have some sense of their own exposure. We define high risk interactions based on proximity with someone who reported to have COVID-19 or to show high risk symptomps and when. 
                  </Card.Text>
                </Card>
                <Card style={cardStyelGral}>
                  <Card.Img variant="top" src="images/home_blocked_map.png" />
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="light">
            <Card.Body>
              <CardGroup>
                <Card border="light">
                  <Card.Img variant="top" src="images/home_profile_image.png" />
                </Card>
                <Card border="light">
                  <Card.Title>Share your location data with privacy</Card.Title>
                  <Card.Text>
                    Using Google Takeout, share your "<b>Location History</b>",
                  Covid19 test rsults and symptoms. Your data  will be encrypted locally
                  and will never be revealed to any entity.
                  </Card.Text>
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="light">
            <Card.Body>
              <CardGroup>
                <Card border="light">
                  <Card.Title>Map View</Card.Title>
                  <Card.Text>
                    See a “heatmap” of  high risk areas where users who have reported positive test results and users who have reported high risk symptoms have travelled. Use the global view to be informed about and avoid “high risk” areas.
                  </Card.Text>
                </Card>
                <Card border="light">
                  <Card.Img variant="top" src="images/home_map.png" />
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="light">
            <Card.Body>
              <CardGroup>
                <Card border="light">
                  <Card.Title>Ensuring your privacy and protection</Card.Title>
                  <Card.Text>
                  The technology behind how their data is secure. If your location history is turned off, you can upload your history manually to Google Takeout using their Timeline. Just select a point in time on the upper left hand corner and manually enter your previous locations by date.
                  </Card.Text>
                </Card>
                <Card border="light">
                  
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          
        </div>
      </div>
    );
  }
}
export default Home;
