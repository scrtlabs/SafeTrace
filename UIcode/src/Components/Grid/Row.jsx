import styled from "styled-components";

const Col = styled.div`
  display: flex;
  flex-direction: row;
  padding: 12px 0;
  & > button:not(:first-child) {
    margin: 0 10px;
  }
`;

export default Col;
