import styled from "styled-components";
import colors from "Theme/colors";

export default styled.button`
  display: flex;
  align-items: center;
  border: 1px solid 
  ${props => (props.selected ? colors.primary.main : colors.grey.light)};
  transition: .5s;

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
