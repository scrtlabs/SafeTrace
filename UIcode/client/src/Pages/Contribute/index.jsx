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
import { report } from "Services/api";
import { addData } from "Services/enclave";
import Authorized from "Sections/Authorized";

const Wrapper = styled.div`
  padding-top: 50px;
`;

const Contribute = ({ history }) => {
  const [step, setStep] = useState(0);
  const [testResult, setTestResult] = useState("positive");
  const [testDate, setTestDate] = useState(null);
  const { jwtToken, me } = useContext(authContext);
  const [errors, setErrors] = useState([]);
  const showButtons = step === 1;

  const nextPage = () => setStep((step) => step + 1);

  const sendReport = () =>
    report({
      token: jwtToken,
      data: {
        idUser: me.idUser,
        testDate,
        testResult: testResult === "positive" ? 1 : 0,
      },
    })
      .then(nextPage)
      .catch((e) => {
        if (e?.response?.data?.errors) {
          setErrors(e.response.data.errors);
        } else {
          alert("error");
        }
      });

  const handleFileSubmit = (file) => {
    parseJsonFile(file)
      .then((json) => {
        const data = convertLocationData(json);
        addData(me.encryptedUserId, JSON.stringify(data))
          .then(() => {
            history.push(
              "/results",
              "Your data has been successfully shared with SafeTrace API."
            );
          })
          .catch(() => alert("An error occurred. Please try again"));
      })
      .catch(() => alert("Invalid file"));
  };

  const handleTestDateChange = (date) => setTestDate(date);
  const handleNextClick = () => {
    if (step === 1) {
      sendReport();
    } else {
      nextPage();
    }
  };

  const handleBackClick = () => setStep((step) => step - 1);
  const onFileChange = (f) => {
    parseJsonFile(f).catch(() => alert("Invalid file"));
  };

  const steps = [
    () => <Step1 submitReport={handleNextClick} viewResults={() => {}} />,
    () => (
      <Step2
        selectedTestResult={testResult}
        onTestResultChange={setTestResult}
        testDate={testDate}
        onTestDateChange={handleTestDateChange}
        errors={errors}
      />
    ),
    () => <Step3 onFileChange={onFileChange} onSubmit={handleFileSubmit} />,
  ];

  const CurrentStep = steps[step];

  return (
    <Wrapper>
      <Authorized alternative={LoginForm}>
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
      </Authorized>
    </Wrapper>
  );
};

export default Contribute;
