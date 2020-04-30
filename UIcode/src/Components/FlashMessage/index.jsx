import React from "react";
import styled from "styled-components";
import colors from "Theme/colors";
import Flash from "./Flash";

const Msg = styled.span`
  color: ${(props) =>
    props.type === "success"
      ? colors.success.main
      : props.type === "error"
      ? colors.error.main
      : colors.text.main};
`;

const FlashMessage = () => {
  const { message, type } = Flash.get();

  return message ? <Msg type={type}>{message}</Msg> : null;
};

export default FlashMessage;
