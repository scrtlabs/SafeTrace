import React, { useState } from "react";

export const authContext = React.createContext({});

const { Provider } = authContext;

const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(null);

  return <Provider value={{ token, setToken }}>{children}</Provider>;
};

export default AuthProvider;
