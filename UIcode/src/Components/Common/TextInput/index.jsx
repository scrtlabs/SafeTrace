import React from "react";
import styled from "styled-components";
import colors from "Theme/colors";

const StyledInput = styled.input`
  height: ${props =>
    props.size === "big" ? "32px" : props.size === "default" ? "24px" : "18px"};
  font-size: 24px;
  border-radius: 6px;
  border: 1px solid
    ${props =>
      typeof props.valid === "boolean"
        ? props.valid
          ? colors.success.main
          : colors.error.main
        : colors.grey.light};
  outline: none;
  width: 100%;
  padding: 16px;

  &:focus {
    border-color: ${colors.primary.main};
  }

  &::placeholder {
    color: ${colors.grey.main};
  }

  transition: 0.5s;
  box-sizing: content-box;
  margin: 0 9px;
`;

const TextInput = ({
  value,
  validator,
  size = "default",
  onChange,
  ...restProps
}) => {
  const updateValue = e => {
    onChange(e.currentTarget.value);
  };
  return (
    <StyledInput
      value={value}
      valid={validator(value)}
      {...restProps}
      onChange={updateValue}
      size={size}
    />
  );
};

export default TextInput;
