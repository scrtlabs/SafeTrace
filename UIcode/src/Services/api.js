import Axios from "axios";

export const report = ({ token, data: { idUser, testDate, testResult } }) => {
  return Axios.post(
    `${process.env.REACT_APP_API_URL}/report`,
    {
      idUser,
      testDate,
      testResult,
    },
    { headers: { "x-access-token": token } }
  );
};