import React from "react";
import RadioGroup from "Components/RadioGroup";
import DatePicker from "Components/DatePicker";
import Box from "Styled/Box";

const Step2 = ({
  selectedTestResult,
  onTestResultChange,
  testDate,
  onTestDateChange,
}) => {
  return (
    <>
      <h2>Self Report</h2>
      <hr />
      <h3>Do you have test results for COVID-19?</h3>
      <p>
        All data is private and anonymous. You can still report your data to
        this map if you haven’t taken a test, and update test results later.{" "}
      </p>
      <RadioGroup selected={selectedTestResult} onChange={onTestResultChange}>
        {[
          {
            label: "Positive",
            value: "positive",
          },
          {
            label: "Negative",
            value: "negative",
          },
          {
            label: "I have not been tested",
            value: "not_tested",
          },
        ]}
      </RadioGroup>

      <hr />
      <Box>
        <h2>What date was the test administered?</h2>
        <DatePicker
          value={testDate}
          onDayChange={onTestDateChange}
          disabled={selectedTestResult === "not_tested"}
        />
      </Box>
    </>
  );
};

export default Step2;
