import React, { useContext } from "react";
import { useState } from "react";
import styled from "styled-components";
import Button from "Components/Common/Button";
import Row from "Components/Grid/Row";
import Step1 from "./Step1";
import Step2 from "./Step2";
import { authContext } from "Providers/AuthProvider";
import LoginForm from "Sections/LoginForm";
import Step3 from "./Step3";
import { parseJsonFile, convertLocationData } from "Services/parser";

const Wrapper = styled.div`
  padding-top: 50px;
`;

const Contribute = () => {
  const [step, setStep] = useState(0);
  const [selectedTestResult, setSelectedTestResult] = useState("positive");
  const [testDate, setTestDate] = useState(null);
  const { isLoggedIn } = useContext(authContext);

  const showButtons = step === 1;

  const handleTestDateChange = (date) => setTestDate(date);
  const handleNextClick = () => setStep((step) => step + 1);
  const handleBackClick = () => setStep((step) => step - 1);
  const onFileChange = (f) => {
    parseJsonFile(f).then(
      (json) => {
        console.log(convertLocationData(json));
      },
      () => alert("Invalid file")
    );
  };

  const steps = [
    () => <Step1 submitReport={handleNextClick} viewResults={() => {}} />,
    () => (
      <Step2
        selectedTestResult={selectedTestResult}
        onTestResultChange={setSelectedTestResult}
        testDate={testDate}
        onTestDateChange={handleTestDateChange}
      />
    ),
    () => <Step3 onFileChange={onFileChange} />,
  ];

  const CurrentStep = steps[step];

  return (
    <Wrapper>
      {isLoggedIn ? (
        <>
          <CurrentStep />
          {showButtons && (
            <Row>
              <Button color="secondary" onClick={handleBackClick}>
                Back
              </Button>

              <Button color="primary" onClick={handleNextClick}>
                Next
              </Button>
            </Row>
          )}
        </>
      ) : (
        <LoginForm />
      )}
    </Wrapper>
  );
};

export default Contribute;
