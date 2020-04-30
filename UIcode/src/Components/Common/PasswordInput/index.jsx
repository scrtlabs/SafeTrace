import React from "react";
import TextInput from "../TextInput";

const validator = value => (!value ? null : value.length < 8);

const PasswordInput = ({ ...restProps }) => {
  return <TextInput {...restProps} type="password" validator={validator} />;
};

export default PasswordInput;
