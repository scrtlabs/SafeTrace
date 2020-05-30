import React from "react";
import { Card, Button, CardColumns, CardGroup } from "react-bootstrap";
import styled from "styled-components";
import 'typeface-roboto';
import '../../custom.css';

const cardStyelGral = {
  paddding: "3%"
};

const buttonblue = {
  width: "208px",
  "font-size": "22px"
}




class Home extends React.Component {
  render() {
    return (
      <div>
        <div>
          <Card border="white">
            <Card.Body style={cardStyelGral}>
              <CardGroup>
                <Card border="white">
                  <Card.Title>
                    Yours privacy matters.Help to Combat COVID-19 safely and
                    securely
              </Card.Title>
                  <Card.Text>
                    Privately share your location history and compare it with other
                    anonymous users
              </Card.Text>
                  <Button variant="primary" style={buttonblue} href="/contribute">I want to help</Button>

                </Card>
                <Card border="white">

                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <hr />
          <Card border="white">
            <Card.Body>
              <Card.Title>
                How it works
              </Card.Title>
              <CardGroup>
                <Card border="white" style={cardStyelGral}>
                  <Card.Subtitle>Share your location data with privacy</Card.Subtitle>
                  <Card.Text>
                    Using <Card.Link href={"https://takeout.google.com/"} target="_blank" >Google Takeout</Card.Link>, share your "<b>Location History</b>",
                  Covid19 test rsults and symptoms. Your data  will be encrypted locally
                  and will never be revealed to any entity.
                  </Card.Text>
                </Card>
                <Card border="white" style={cardStyelGral}>
                  <Card.Img variant="top" src="images/home_blocked_map.png" />
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="white">
            <Card.Body>
              <CardGroup>
                <Card border="white">
                  <Card.Img variant="top" src="images/home_profile_image.png" />
                </Card>
                <Card border="white">
                  <Card.Subtitle>Individual Reporting</Card.Subtitle>
                  <Card.Text>
                    See the times and the locations where you had high risk interactions so that users may have some sense of their own exposure. We define high risk interactions based on proximity with someone who reported to have COVID-19 or to show high risk symptomps and when.
                  </Card.Text>
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="white">
            <Card.Body>
              <CardGroup>
                <Card border="white">
                  <Card.Subtitle>Map View <img src="images/home_stars.png" /></Card.Subtitle>
                  <Card.Text>
                    See a “heatmap” of  high risk areas where users who have reported positive test results and users who have reported high risk symptoms have travelled. Use the global view to be informed about and avoid “high risk” areas.
                  </Card.Text>
                </Card>
                <Card border="white">
                  <Card.Img variant="top" src="images/home_map.png" />
                </Card>
              </CardGroup>
            </Card.Body>
          </Card>
          <Card border="white">
            <Card.Body>
              <CardGroup>
                <Card border="white">
                  <Card.Title>Ensuring your privacy and protection</Card.Title>
                  <Card.Text>
                    The technology behind how their data is secure. If your location history is turned off, you can upload your history manually to Google Takeout using their <Card.Link href={"https://takeout.google.com/"} target="_blank" >Timeline</Card.Link>. Just select a point in time on the upper left hand corner and manually enter your previous locations by date.
                  </Card.Text>
                </Card>
                <Card border="white">

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
