import React from "react";
import styled, { css } from "styled-components";
import colors from "Theme/colors";

const colorStyles = {
  primary: css`
    background-color: ${colors.primary.main};
    color: white;
    &:hover {
      background-color: ${colors.primary.light};
    }
    &:active {
      background-color: ${colors.primary.dark};
    }
  `,
  secondary: css`
    background-color: white;
    color: ${colors.primary.main};
    border-color: ${colors.grey.light};
    &:hover {
      border-color: ${colors.primary.main};
    }
  `
};

const StyledButton = styled.button`
  height: ${props =>
    props.size === "big" ? "56px" : props.size === "default" ? "48px" : "32px"};
  font-size: 24px;
  border-width: 1px;
  border-style: solid;
  outline: none;
  padding: auto 24px;
  min-width: 200px;
  transition: 0.5s;
  box-sizing: content-box;
  cursor: pointer;
  font-weight: bold;

  ${props => colorStyles[props.color]}
`;

const Button = ({
  children,
  color = "secondary",
  size = "default",
  ...restProps
}) => {
  return (
    <StyledButton color={color} size={size} {...restProps}>
      {children}
    </StyledButton>
  );
};

export default Button;
