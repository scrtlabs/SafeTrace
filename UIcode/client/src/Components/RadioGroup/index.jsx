import React from "react";
import styled from "styled-components";
import colors from "Theme/colors";
import ListItemButton from "Styled/ListItemButton";
import Ul from "Styled/Ul";
import Li from "Styled/Li";

const CheckBox = styled.div`
    border-radius: 50%;
    height: 30px;
    width: 30px;
    margin-right: 10px;
    position: relative;
    transition .5s;
    border: 1px solid
      ${props => (props.selected ? colors.primary.main : colors.grey.light)};
    ${props => props.selected && `background-color: ${colors.primary.main}`};
    ${props =>
      props.selected &&
      `&::after {
      content: "\\2713";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      font-size: 30px;
      line-height: 30px;
      color: white;
    }`}
  `;
const RadioGroup = ({ children, selected, onChange }) => {
  const handleRadioButtonClick = value => () => onChange(value);
  return (
    <Ul>
      {children.map(({ label, value }) => (
        <Li key={value}>
          <ListItemButton
            onClick={handleRadioButtonClick(value)}
            selected={value === selected}
          >
            <CheckBox selected={value === selected} />
            {label}
          </ListItemButton>
        </Li>
      ))}
    </Ul>
  );
};

export default RadioGroup;
