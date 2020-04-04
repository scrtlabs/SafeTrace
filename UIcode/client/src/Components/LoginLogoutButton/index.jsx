import React from "react";
import { GoogleLogin, GoogleLogout } from "react-google-login";
import NavLinkStyle from "Styled/NavLink";
import styled from "styled-components";
import { googleLoginToApi } from "Services/auth";
import { useContext } from "react";
import { authContext } from "Providers/AuthProvider";

const StyledButton = styled.button`
  ${NavLinkStyle}
`;

const LoginLogoutButton = ({ defaultButton = false }) => {
  const { token, setToken } = useContext(authContext);

  const loginSuccess = (response) => {
    setToken(response.tokenId);
    googleLoginToApi(response.tokenId).then(console.log, console.log);
  };

  const loginFail = (response) => {
    alert("Login failed");
  };

  const onLogout = (response) => {
    setToken(null);
  };

  const render = defaultButton
    ? (text) => undefined
    : (text) => ({ onClick, disabled }) => (
        <StyledButton onClick={onClick} disabled={disabled}>
          {text}
        </StyledButton>
      );

  console.log({ token });
  return token ? (
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
