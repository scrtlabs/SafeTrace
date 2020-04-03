import { css } from "styled-components";
import colors from "Theme/colors";

export default css`
  font-size: 16px;
  color: rgba(0, 0, 0, 0.9);
  font-weight: 400;
  display: inline-block;
  min-width: 100px;
  text-align: center;
  height: 100%;
  background: none;
  border: none;
  padding: 0;
  text-decoration: none;
  cursor: pointer;
  outline: none;

  &:hover {
    text-decoration: none;
    color: blue;
  }

  &.active {
    color: ${colors.secondary.main};
    border-bottom: 2px solid blue;
  }
`;
