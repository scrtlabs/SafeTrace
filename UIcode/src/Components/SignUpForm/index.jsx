import React, { useState } from "react";
import styled from "styled-components";
import EmailInput from "Components/Common/EmailInput";
import PasswordInput from "Components/Common/PasswordInput";
import Button from "Components/Common/Button";
import Col from "Components/Grid/Col";
import Row from "Components/Grid/Row";

const SignUpFormWrapper = styled.div`
  width: 400px;
  margin: 0 auto;
  margin-top: 45px;
`;

const SignUpForm = ({ onSubmit }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmitButton = () => {
    onSubmit(email, password);
  };
  
  return (
    <SignUpFormWrapper>
      <Col>
        <Row>
          <EmailInput value={email} onChange={setEmail} placeholder="Email" />
        </Row>
        <Row controlId="password">
          <PasswordInput
            value={password}
            onChange={setPassword}
            placeholder="Password"
          />
        </Row>
        {/*<Row>
          <Form.Check type="checkbox" label="Check me out" />
        </Row>*/}
        <Row>
          <Button color="primary" type="submit" onClick={handleSubmitButton}>
            Submit
          </Button>
        </Row>
      </Col>
    </SignUpFormWrapper>
  );
};

export default SignUpForm;
