import React from "react";
import ListItemButton from "Styled/ListItemButton";
import Ul from "Styled/Ul";
import Li from "Styled/Li";
import Box from "Styled/Box";

const Step1 = ({ submitReport, viewResults }) => {
  return (
    <Box>
      <h2>What would you like to do?</h2>
      <Ul>
        <Li>
          <ListItemButton onClick={submitReport}>
            I want to Self Report
          </ListItemButton>
        </Li>
        <Li>
          <ListItemButton onClick={viewResults}>View my results</ListItemButton>
        </Li>
      </Ul>
    </Box>
  );
};

export default Step1;
