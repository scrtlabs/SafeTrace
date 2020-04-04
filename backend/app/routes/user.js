const express = require("express");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();
const auth = require("../middleware/auth");
const {OAuth2Client} = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const config = require('../config/config.js');
const crypto = require('../helpers/crypto');

const User = require("../models/user");


/**
 * @method - POST
 * @param - /signup
 * @description - User SignUp
 * @param {string} username
 * @param {string} email
 * @param {string} password
 * @param {string} agreeToBeNotified
 * @returns {json} token
 */


router.post(
    "/signup",
    [
        check("username", "Please Enter a Valid Username")
            .not()
            .isEmpty(),
        check("email", "Please enter a valid email").isEmail(),
        check("password", "Please enter a valid password").isLength({
            min: 6
        }),
        check("agreeToBeNotified", "Please enter true or false").isBoolean()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const {
            username,
            email,
            password,
            agreeToBeNotified,
        } = req.body;
        console.log('body', req.body);
        try {
            let user = await User.findOne({
                email
            });
            if (user) {
                return res.status(400).json({
                    msg: "User Already Exists"
                });
            }
            const encryptedUserId = crypto.encrypt(email).encryptedData;
            
            user = new User({
                username,
                email,
                password,
                encryptedUserId,
                agreeToBeNotified
            });

            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                "randomString", {
                expiresIn: 10000
            },
                (err, token) => {
                    if (err) throw err;
                    res.status(200).json({
                        token
                    });
                }
            );
        } catch (err) {
            console.log(err.message);
            res.status(500).send("Error in Saving");
        }
    }
);

/**
 * @method - POST
 * @param - /login
 * @description - User login
 * @param {string} email
 * @param {string} password
 * @returns {json} token
 */


router.post(
    "/login",
    [
        check("email", "Please enter a valid email").isEmail(),
        check("password", "Por favor, ingrese un password válido").isLength({
            min: 6
        })
    ],
    async (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { email, password } = req.body;
        try {
            let user = await User.findOne({
                email
            });
            if (!user)
                return res.status(400).json({
                    message: "User Not Exist"
                });

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch)
                return res.status(400).json({
                    message: "Incorrect Password!"
                });

            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                config.secret,
                {
                    expiresIn: 3600  //1 hour without activity
                },
                (err, token) => {
                    if (err) throw err;
                    res.status(200).json({
                        token
                    });
                }
            );
        } catch (e) {
            console.error(e);
            res.status(500).json({
                message: "Server Error"
            });
        }
    }
);


/**
* @method - POST
* @param - /glogin
* @description - Google login user
* @param - google token
* @returns {string} 
*/

router.post(
    "/glogin",
    [
        check("token", "Google token user is required").notEmpty()
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { token } = req.body;

        const params = {
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
            // Or, if multiple clients access the backend:
            //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
        }

        
        try {
            //Validate google account
            const ticket = await client.verifyIdToken(params);
            
            const payload = ticket.getPayload();
            const userid = payload['sub'];
            const username = payload['given_name']+' '+payload['family_name'];
            console.log('payload', payload);
            
            const { email } = payload;

            let user = await User.findOne({
                email
            });
            
            if (!user) { //If google user doesn't exist, add it to the user collection
                
                const encryptedUserId = crypto.encrypt(email).encryptedData;
                const password = userid;
                const userType = 1; //Google account type
                const agreeToBeNotified = 0;

                user = new User({
                    username,
                    email,
                    password,
                    encryptedUserId,
                    agreeToBeNotified,
                    userType
                });

                const salt = await bcrypt.genSalt(10);
                user.password = await bcrypt.hash(password, salt);

                await user.save();

                const payload = {
                    user: {
                        id: user.id
                    }
                };
            
                return res.status(200).json({
                    message: "User added and logged in"
                });

            }else{
                return res.status(200).json({
                    message: "User is logged in"
                });
            }
            
        } catch (e) {
            console.error(e);
            res.status(500).json({
                message: "Server Error",
            });
        }
        // If request specified a G Suite domain:
        //const domain = payload['hd'];
    }
);

/**
* @method - GET
* @description - Get LoggedIn User
* @param - 
* @header token
*/

router.get("/me", auth, async (req, res) => {
    try {
        // request.user is getting fetched from Middleware after token authentication
        const user = await User.findById(req.user.id);
        user.password  = '---';
        res.json(user);
    } catch (e) {
        res.send({ message: "Error in Fetching user" });
    }
});

/**
* @method - GET
* @description - Get Google LoggedIn User
* @param 
* @header token (google token)
*/

router.get("/gme",[] ,async (req, res) => {
    const token = req.header("token");
    if (!token) return res.status(401).json({ message: "Auth Error" });

    try {
        const params = {
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
        }
        
        const ticket = await client.verifyIdToken(params);           
        const payload = ticket.getPayload();
        const email = payload['email'];
        const user = await User.findOne({
            email
        });
        if (!user)
            return res.status(400).json({
                message: "User Not Exist"
            });
        user.password  = '---';
        res.json(user);
        console.log('payload', payload);
    } catch (e) {
        console.error(e);
        res.status(500).send({ message: "Invalid Token" });
    }
    
});

module.exports = router;