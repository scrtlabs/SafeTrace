import React from "react";
import styled from "styled-components";

const StyledTable = styled.table`
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  & > thead > tr > th {
    border: none;
    vertical-align: baseline;
    padding: 0.75rem;
    & > p {
      font-size: 14px;
      font-weight: normal;
    }
  }
`;

const ResultsTable = ({ results }) => {
  return (
    <StyledTable>
      <thead>
        <tr>
          <th>Location</th>
          <th>Address</th>
          <th>
            Number of Matches
            <p>
              How many individuals who have COVID-19 have been in this location
              in the past 12 hours.
            </p>
          </th>
          <th>Date</th>
          <th>
            Time
            <p>
              the amount of time between your visit and the most recent match
            </p>
          </th>
        </tr>
      </thead>
      <tbody>
        {results &&
          results.map((result) => (
            <tr key={result.location + result.address + result.date}>
              <td>{result.location}</td>
              <td>{result.address}</td>
              <td>{result.numberOfMatches}</td>
              <td>{result.date}</td>
              <td>{result.time}</td>
            </tr>
          ))}
      </tbody>
    </StyledTable>
  );
};

export default ResultsTable;
