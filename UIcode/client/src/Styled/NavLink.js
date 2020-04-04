import { css } from "styled-components";
import colors from "Theme/colors";

export default css`
  font-size: 16px;
  color: rgba(0, 0, 0, 0.9);
  font-weight: 400;
  display: inline-block;
  text-align: center;
  height: 100%;
  background: none;
  border: none;
  padding: 0 2px;
  text-decoration: none;
  cursor: pointer;
  outline: none;
  transition: 0.5s;

  &:hover {
    text-decoration: none;
    color: rgba(0, 0, 0, 0.9);
  }

  &:not(.active):not(active):hover,
  &:not(.active):not(active):focus {
    color: ${colors.primary.main};
    outline: none;
  }

  &.active,
  &:active {
    text-shadow: 1px 0 0 rgba(0, 0, 0, 0.9);
    border-bottom: 2px solid blue;
    outline: none;
  }
`;
