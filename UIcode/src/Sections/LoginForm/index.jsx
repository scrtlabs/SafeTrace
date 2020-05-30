import React from "react";
import Box from "Styled/Box";
import LoginLogoutButton from "Components/LoginLogoutButton";

const LoginForm = () => {
  return (
    <Box>
      <h2>Login</h2>
      <p>
        Thank you for offering to help! The more people who participate, the
        more effective contact tracing can be.
      </p>
      <LoginLogoutButton defaultButton />
    </Box>
  );
};

export default LoginForm;
