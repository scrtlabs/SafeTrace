import React from "react";
import styled from "styled-components";
import { NavLink } from "react-router-dom";
import NavLinkStyle from "Styled/NavLink";
import LoginLogoutButton from "Components/LoginLogoutButton";

const HeaderWrapper = styled.header`
  width: 100%;
  display: flex;
  justify-content: space-between;
  border-bottom: 1px #dee2e6 solid;
  margin: 20px 0;
  padding: 0 30px;
`;

const StyledNavBar = styled.nav`
  display: flex;
  padding: 0 15px;
  padding-left: 15px;
  margin: 0;
  width: 100%;
  justify-content: space-between;
`;

const NavUl = styled.ul`
  display: flex;
  align-items: stretch;
  list-style: none;
  margin: 0;
  padding: 0;
  height: 40px;
`;

const Title = styled.h1`
  font-size: 16px;
  width: 400px;
  text-align: Center;
  display: inline-block;
  font-weight: 600;
  padding: 0;
  margin: 0;
`;

const StyledNavLink = styled(NavLink)`
  ${NavLinkStyle}
`;

const Header = () => {
  return (
    <HeaderWrapper>
      <StyledNavBar>
        <NavUl>
          <li>
            <StyledNavLink to="/" exact>
              Home
            </StyledNavLink>
          </li>
          <li>
            <StyledNavLink to="/API" exact>
              API
            </StyledNavLink>
          </li>
          <li>
            <StyledNavLink to="/contribute">Contribute</StyledNavLink>
          </li>
        </NavUl>

        <Title>Covid-19 Safe Trace</Title>

        <NavUl>
          <li>
            <LoginLogoutButton />
          </li>
        </NavUl>
      </StyledNavBar>
    </HeaderWrapper>
  );
};

export default Header;
