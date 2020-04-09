import React from "react";
import styled from "styled-components";

import LoginForm from "Sections/LoginForm";

import Authorized from "Sections/Authorized";
import Box from "Styled/Box";
import ResultsTable from "./ResultsTable";
import FlashMessage from "FlashMessage";

const Wrapper = styled.div`
  padding-top: 50px;
`;

const Results = ({ location }) => {
  return (
    <Wrapper>
      <FlashMessage location={location} />
      <Authorized alternative={LoginForm}>
        {}
        <Box>
          <h2>Here are your results:</h2>
          <ResultsTable />
        </Box>
      </Authorized>
    </Wrapper>
  );
};

export default Results;
