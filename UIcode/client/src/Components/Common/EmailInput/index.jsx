import React from "react";
import TextInput from "../TextInput";
import { isValidEmail } from "Utils/validation";

const validator = value => (!value ? null : isValidEmail(value));

const EmailInput = ({ ...restProps }) => {
  return <TextInput {...restProps} type="email" validator={validator} />;
};

export default EmailInput;
