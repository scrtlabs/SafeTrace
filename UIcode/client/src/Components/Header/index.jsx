import React from "react";
import styled from "styled-components";
import { NavLink } from "react-router-dom";
import NavLinkStyle from "Styled/NavLink";
import LoginLogoutButton from "Components/LoginLogoutButton";

const HeaderWrapper = styled.header`
  width: 100%;
  max-width: 1140px;
  display: flex;
  justify-content: space-between;
  margin: 20px auto 0;
  padding: 0;
`;

const StyledNavBar = styled.nav`
  display: flex;
  width: 100%;
  justify-content: space-between;
`;

const NavUl = styled.ul`
  display: flex;
  align-items: stretch;
  justify-content: space-between;
  list-style: none;
  margin: 0;
  padding: 0;
  height: 40px;
  flex: 1;
`;

const Title = styled.h1`
  font-size: 16px;
  width: 400px;
  text-align: Center;
  display: inline-block;
  font-weight: 600;
  padding: 0;
  margin: 0;
  flex: 2;
`;

const StyledNavLink = styled(NavLink)`
  ${NavLinkStyle}
`;

const Header = ({ className }) => {
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
