import React, { useContext } from "react";
import { authContext } from "Providers/AuthProvider";
import DotLoader from "react-spinners/DotLoader";

const Authorized = ({ children, alternative = null }) => {
  const { isLoggedIn, loading } = useContext(authContext);

  const AlternativeComponent = alternative ? alternative : () => "";
  return loading ? (
    <DotLoader loading={loading} size={150}/>
  ) : isLoggedIn ? (
    children
  ) : (
    <AlternativeComponent />
  );
};

export default Authorized;
