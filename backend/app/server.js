const express = require('express');
const http = require('http');
const fs = require('fs');
const app = express();
const mongoose = require('mongoose');
const {OAuth2Client} = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

var cors = require('cors');

const bodyParser = require("body-parser");
const user = require("./routes/user");
const report = require("./routes/report");

require('dotenv').config({ path: '.env' })


mongoose.connect(process.env.MONGOURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}, (err) => {
    if (err) throw err;
    console.log("connected to mongo");
});

// Middleware
app.use(bodyParser.json());
app.use(cors());

app.get('/', (req, res) => {
    res.send("SafeTrace backend API")
});

/**
 * Router Middleware
 * Router - /user/*
 * Method - *
 */
app.use("/user", user);

/**
 * Router Middleware
 * Router - /report
 * Method - *
 */
app.use("/report", report);

console.log(process.env.PORT);

http.createServer(app).listen(process.env.PORT || 4080, () => {
    console.log(`Server running -> PORT ${process.env.PORT}`)
});

