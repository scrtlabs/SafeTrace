import Axios from "axios";
import Cookies from "js-cookie";

export const getToken = () => {
  return Cookies.get("token");
};

export const googleLoginToApi = (token) => {
  return Axios.post(`${process.env.REACT_APP_API_URL}/user/glogin`, {
    token,
  });
};

export const getMe = (token) => {
  return Axios.get(
    `${process.env.REACT_APP_API_URL}/user/me`,

    {
      headers: {
        authorization: token,
      },
    }
  );
};
