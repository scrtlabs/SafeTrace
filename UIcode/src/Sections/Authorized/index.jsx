import React, { useContext } from "react";
import { authContext } from "Providers/AuthProvider";

const Authorized = ({ children, alternative = null }) => {
  const { isLoggedIn } = useContext(authContext);

  const AlternativeComponent = alternative ? alternative : () => "";
  return isLoggedIn ? children : <AlternativeComponent />;
};

export default Authorized;