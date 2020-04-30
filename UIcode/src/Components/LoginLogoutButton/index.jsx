import React, { useCallback } from "react";
import { GoogleLogin, GoogleLogout } from "react-google-login";
import NavLinkStyle from "Styled/NavLink";
import styled from "styled-components";
import { useContext } from "react";
import { authContext } from "Providers/AuthProvider";

const StyledButton = styled.button`
  ${NavLinkStyle}
`;

const LoginLogoutButton = ({ defaultButton = false }) => {
  const { googleToken, loginWithGoogleToken, logout } = useContext(authContext);

  const loginSuccess = useCallback(
    (response) => {
      loginWithGoogleToken(response.tokenId);
    },
    [loginWithGoogleToken]
  );

  const loginFail = (response) => {
    alert("Login failed");
  };

  const onLogout = (response) => {
    logout();
  };

  const render = defaultButton
    ? (text) => undefined
    : (text) => ({ onClick, disabled }) => (
        <StyledButton onClick={onClick} disabled={disabled}>
          {text}
        </StyledButton>
      );

  return googleToken ? (
    <GoogleLogout
      clientId={process.env.REACT_APP_GOOGLE_CLIENT_ID}
      buttonText="Logout"
      onLogoutSuccess={onLogout}
      onFailure={onLogout}
      render={render("Logout")}
    />
  ) : (
    <GoogleLogin
      clientId={process.env.REACT_APP_GOOGLE_CLIENT_ID}
      buttonText="Login"
      onSuccess={loginSuccess}
      onFailure={loginFail}
      cookiePolicy={"single_host_origin"}
      isSignedIn
      render={render("Login")}
    />
  );
};

export default LoginLogoutButton;
