const jwt = require("jsonwebtoken");
const config = require('../config/config.js');


module.exports = function(req, res, next) {
  let userType = req.headers['auth-user-type'] || 0;
  let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase

  if (!token) return res.status(401).json({ message: "Auth Error" });
  
  try {
    const decoded = jwt.verify(token, config.secret);
    req.user = decoded.user;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).send({ message: "Invalid Token" });
  }
};


