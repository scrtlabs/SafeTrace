import React, { useState, useCallback } from "react";
import Cookies from "js-cookie";
import { googleLoginToApi, getMe } from "Services/auth";

export const authContext = React.createContext({});

const { Provider } = authContext;

const AuthProvider = ({ children }) => {
  const [googleToken, setGoogleToken] = useState();
  const [jwtToken, setJwtTokenState] = useState(Cookies.get("jwt") || null);
  const [user, setUser] = useState(Cookies.getJSON("user") || null);

  const setJwtToken = useCallback((token) => {
    setJwtTokenState(token);
    if (!token) {
      Cookies.remove("jwt");
    } else {
      Cookies.set("jwt", token);
    }
  }, []);

  const setMe = useCallback((me) => {
    setUser(me);
    if (!me) {
      Cookies.remove("user");
    } else {
      Cookies.set("user", me);
    }
  }, []);

  const loginWithGoogleToken = async (googleToken) => {
    const {
      data: { token },
    } = await googleLoginToApi(googleToken);
    const { data: me } = await getMe(token);

    setGoogleToken(googleToken);
    setJwtToken(token);
    setMe(me);
  };

  const logout = async () => {
    setMe(() => {
      setGoogleToken(null);
      setJwtToken(null);
      return null;
    });
  };

  const isLoggedIn = googleToken && jwtToken && user;

  return (
    <Provider
      value={{
        googleToken,
        loginWithGoogleToken,
        logout,
        jwtToken,
        me: user,
        isLoggedIn,
      }}
    >
      {children}
    </Provider>
  );
};

export default AuthProvider;
