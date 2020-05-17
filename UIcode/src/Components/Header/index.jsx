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
  justify-content: ${(props) =>
    props.align === "right" ? `flex-end` : `space-between`};
  list-style: none;
  margin: 0;
  padding: 0;
  height: 40px;
`;

const NavLi = styled.li`
  &:not(:first-child):not(:last-child):not(:only-child) {
    margin: 0 32px;
  }
  :first-child:not(:only-child) {
    margin-right: 32px;
  }
  :last-child:not(:only-child) {
    margin-left: 32px;
  }
`;

const Title = styled.h1`
  width: 250px;
  margin-left: -50px;
  display: inline-block;
  font-family: Roboto;
  font-style: normal;
  font-weight: bold;
  font-size: 24px;
  line-height: 26px;
/* identical to box height, or 108% */


color: #383838;
`;

const StyledNavLink = styled(NavLink)`
  ${NavLinkStyle}
`;

const Header = ({ className }) => {
  return (
    <HeaderWrapper>
      <StyledNavBar>
        <NavUl>
          <NavLi>
            <StyledNavLink to="/" exact>
              Home
            </StyledNavLink>
          </NavLi>
          <NavLi>
            <StyledNavLink to="/API" exact>
              API
            </StyledNavLink>
          </NavLi>
          <NavLi>
            <StyledNavLink
              to="/contribute"
              isActive={(match, location) => {
                return match || location.pathname === "/results";
              }}
            >
              Contribute
            </StyledNavLink>
          </NavLi>
        </NavUl>

        <Title>Covid-19 Safe Trace</Title>

        <NavUl align="right">
          <NavLi>
            <LoginLogoutButton />
          </NavLi>
        </NavUl>
      </StyledNavBar>
    </HeaderWrapper>
  );
};

export default Header;
