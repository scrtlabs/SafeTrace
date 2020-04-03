import React from "react";
import { Route } from "react-router-dom";
import Header from "Components/Header";
import styled from "styled-components";
import Hr from "Components/Grid/Hr";

const Wrapper = styled.div``;

const PageContent = styled.div`
  width: 100%;
  max-width: 1140px;
  margin: 0 auto;
`;
const DefaultLayout = props => {
  const { component: Component, ...restProps } = props;

  return (
    <Route
      {...restProps}
      render={matchProps => (
        <Wrapper>
          <Header />
          <Hr />
          <PageContent>
            <Component {...matchProps} />
          </PageContent>
        </Wrapper>
      )}
    />
  );
};

export default DefaultLayout;
