import React from "react";
import styled from "styled-components";
import colors from "Theme/colors";

const RadioList = styled.ul`
  list-style: none;
  display: flex;
  flex-direction: column;
  margin: 0;
  padding: 0;
`;
const RadioListItem = styled.li`
  margin: 10px 0;
`;

const RadioButton = styled.button`
  display: flex;
  align-items: center;
  border: 1px solid
  ${props => (props.selected ? colors.primary.main : colors.grey.light)};
    height: 60px;
    width: 100%;
    padding: 10px;
    border-radius: 6px;
    background: none;
    cursor: pointer;
    transition .5s;
    &:active,
    &:focus {
      outline: none;
    }
  `;

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
    <RadioList>
      {children.map(({ label, value }) => (
        <RadioListItem key={value}>
          <RadioButton
            onClick={handleRadioButtonClick(value)}
            selected={value === selected}
          >
            <CheckBox selected={value === selected} />
            {label}
          </RadioButton>
        </RadioListItem>
      ))}
    </RadioList>
  );
};

export default RadioGroup;
