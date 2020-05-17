import React from "react";
import Box from "Styled/Box";
import Row from "Components/Grid/Row";
import FileUpload from "Components/FileUpload/index.jsx";

const Step3 = ({ onFileChange, onSubmit }) => {
  return (
    <Box>
      <h2>Self Report</h2>
      <hr />
      <h3>Download your Location History</h3>
      <p>
        Using{" "}
        <a href="https://takeout.google.com/settings/takeout">Google Takeout</a>
        , find your <b>“Location History”</b> and export your file. Unzip your
        downloaded file and locate your most recent month of Location History.
        Here is a step-by-step guide below:
      </p>
      
      <h3>Step 1</h3>
      <p>
        Make sure your <b>“Location History”</b> is turned <b>ON</b> at{" "}
        <a href="https://takeout.google.com/settings/takeout">Google Takeout</a>.
      </p>
      <img src="images/contribute_upload_step1.png" />
      <div style={{height: "50px"}}></div>
      <h3>Step 2</h3>
      <p>
        Download your “<b>“Location History”</b> from{" "}
        <a href="https://takeout.google.com/settings/takeout">Google Takeout</a>.
      </p>
      <img src="images/contribute_upload_step2.png" />
      <div style={{height: "50px"}}></div>
      <h3>Step 3</h3>
      <p>
        Select “export once”, set file type to .zip, and leave the other options
        as they are.
      </p>
      <div style={{height: "50px"}}></div>
      <h3>Step 4</h3>
      <p>
        When you receive your Takeout order from Google, unzip the file and
        locate your most recent month of{" "}
        <b>
          Location History. Takeout > Location History > Semantic Location
          History > 2020 > 2020_MARCH.json
        </b>{" "}
        Can’t find the file?
      </p>
      <Row>
        <FileUpload onChange={onFileChange} onSubmit={onSubmit}/>
      </Row>
    </Box>
  );
};

export default Step3;
