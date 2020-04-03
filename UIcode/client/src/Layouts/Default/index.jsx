import React from "react";
import { Route } from "react-router-dom";
import Header from "Components/Header";
import styled from "styled-components";

const Wrapper = styled.div``;

const DefaultLayout = props => {
  const { component: Component, ...restProps } = props;

  return (
    <Route
      {...restProps}
      render={matchProps => (
        <Wrapper className="container mt-4">
          <Header />
          <Component {...matchProps} />
        </Wrapper>
      )}
    />
  );
};

export default DefaultLayout;
