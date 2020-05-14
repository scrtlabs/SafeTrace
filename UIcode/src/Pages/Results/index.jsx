import React, { useState, useEffect, useContext } from "react";
import styled from "styled-components";
import Axios from "axios";
import { format, formatDistanceToNow, fromUnixTime } from "date-fns";
import LoginForm from "Sections/LoginForm";
import Authorized from "Sections/Authorized";
import FlashMessage from "Components/FlashMessage";
import { findMatch } from "Services/enclave";
import { authContext } from "Providers/AuthProvider";
import { fromLatLng } from "Services/geocode";
import { map } from "Utils/array";
import ResultsTable from "./ResultsTable";

const Wrapper = styled.div`
  padding-top: 50px;
`;

const compareWithMatch = (first) => (second) =>
  first.location === second.location &&
  first.address === second.address &&
  first.date === second.date;

const findMatching = (matches, target) =>
  matches.findIndex(compareWithMatch(target));

const findGeoLocations = async (matches) =>
  Axios.all(matches.map((match) => fromLatLng(match.lat, match.lng))).then(
    map((geocodeResponse, idx) => ({
      idx,
      geocodeResponse,
      enclaveResponse: matches[idx],
    }))
  );

const extractTableData = ({ geocodeResponse, enclaveResponse }) => ({
  location: geocodeResponse.results[0].formatted_address,
  address: geocodeResponse.results[0].formatted_address,
  date: format(enclaveResponse.timestamp, "MM/dd"),
  time: formatDistanceToNow(fromUnixTime(enclaveResponse.timestamp)),
});

const Results = () => {
  const [results, setResults] = useState(null);
  const [request, setRequest] = useState(null);
  const { isLoggedIn, me } = useContext(authContext);
  useEffect(() => {
    if (isLoggedIn && me._id && !request) {
      console.log('me_id',me._id);
      const promise = findMatch(me._id);
      setRequest(promise);
      promise.then((response) => {
        
        if (response.length) {
          findGeoLocations(response).then((res) => {
            console.log('response2',response);
            let res2 = [ res ];
            console.log('findgelocations', res2);
            console.log('filtered', res2.map(extractTableData));

            setResults(
              res2
                .filter(
                  ({ geocodeResponse }) => geocodeResponse.status === "OK"
                )
                .map(extractTableData)
                .reduce((acc, current) => {
                  const existingIdx = findMatching(acc, current);
                  console.log(current);
                  return [
                    ...acc,
                    {
                      location: current.location,
                      address: current.address,
                      date: current.date,
                      time: current.time,
                      numberOfMatches: 1,
                    },
                  ];
                }, [])
            );
            console.log('setResults',results);
          });
        }
      });
    }
  }, [isLoggedIn, me, request]);

  console.log({ results });
  return (
    <Wrapper>
      <FlashMessage />
      <Authorized alternative={LoginForm}>
        <h2>Here are your results:</h2>
        <ResultsTable results={results} />
      </Authorized>
    </Wrapper>
  );
};

export default Results;
