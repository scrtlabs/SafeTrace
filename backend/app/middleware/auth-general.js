const jwt = require("jsonwebtoken");
const config = require('../config/config.js');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = function (req, res, next) {
  let userType = req.headers['auth-user-type'] || 0;
  let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase

  if (!token) return res.status(401).json({ message: "Auth Error" });

  try {

    if (userType === 1) {  //check google token
      const params = {
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
      }
      //const ticket = await client.verifyIdToken(params);

      const guser = (idToken, onSuccess, onFailure) => {
        client.verifyIdToken({ idToken, audiance }) // Bogus client ID is passed into function
          .then(login => {
            onSuccess(login.getPayload()); // This callback gets called!

          })
          .catch(error => {

            if (onFailure)  // Not this one
              res.status(500).send({ message: "Invalid Token2" });
          });
      }

      req.user = guser;

      next();

    } else {  //check internal jwt token
      const decoded = jwt.verify(token, config.secret);
      req.user = decoded.user;
      next();

    }
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Invalid Token1" });
  }
};


