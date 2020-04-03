import React, { useState } from "react";
import { GoogleLogin, GoogleLogout } from "react-google-login";
import NavLinkStyle from "Styled/NavLink";
import styled from "styled-components";
import Cookies from "js-cookie";

const StyledButton = styled.button`
  ${NavLinkStyle}
`;

const LoginLogoutButton = () => {
  const token = Cookies.get("token");

  const [isLoggedIn, setIsLoggedIn] = useState(!!token);

  const loginSuccess = response => {
    Cookies.set("token", response.id_token);
    setIsLoggedIn(true);
  };

  const loginFail = response => {
    alert("Login failed");
  };

  const onLogout = response => {
    Cookies.remove("token");
    setIsLoggedIn(false);
  };

  console.log({ isLoggedIn });
  return isLoggedIn ? (
    <GoogleLogout
      clientId={process.env.REACT_APP_GOOGLE_CLIENT_ID}
      buttonText="Logout"
      onLogoutSuccess={onLogout}
      onFailure={onLogout}
      render={({ onClick, disabled }) => (
        <StyledButton onClick={onClick} disabled={disabled}>
          Logout
        </StyledButton>
      )}
    />
  ) : (
    <GoogleLogin
      clientId={process.env.REACT_APP_GOOGLE_CLIENT_ID}
      buttonText="Login"
      onSuccess={loginSuccess}
      onFailure={loginFail}
      cookiePolicy={"single_host_origin"}
      render={({ onClick, disabled }) => (
        <StyledButton onClick={onClick} disabled={disabled}>
          Login with Google
        </StyledButton>
      )}
    />
  );
};

export default LoginLogoutButton;
