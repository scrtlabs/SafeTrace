import React from "react";
import RadioGroup from "Components/RadioGroup";
import { useState } from "react";
import DatePicker from "Components/DatePicker";
import styled from "styled-components";
import Button from "Components/Common/Button";
import Row from "Components/Grid/Row";

const Box = styled.div`
  width: 500px;
`;
const Contribute = () => {
  const [selected, setSelected] = useState("positive");
  const [date, setDate] = useState(new Date());

  const handleDayChange = day => {
    setDate(day);
  };

  return (
    <div>
      <h2>Self Report</h2>
      <hr />
      <Box>
        <h3>Do you have test results for COVID-19?</h3>
        <p>
          All data is private and anonymous. You can still report your data to
          this map if you haven’t taken a test, and update test results later.{" "}
        </p>
        <RadioGroup selected={selected} onChange={setSelected}>
          {[
            {
              label: "Positive",
              value: "positive"
            },
            {
              label: "Negative",
              value: "negative"
            },
            {
              label: "I have not been tested",
              value: "not_tested"
            }
          ]}
        </RadioGroup>
      </Box>
      <hr />
      <Box>
        <h2>What date was the test administered?</h2>
        <DatePicker selectedDay={date} onDayChange={handleDayChange} />
      </Box>
      <Row>
        <Button color="secondary">Back</Button>
        <Button color="primary">Next</Button>
      </Row>
    </div>
  );
};

export default Contribute;
