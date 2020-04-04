const express = require("express");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();
const auth = require("../middleware/auth-general");
const {OAuth2Client} = require('google-auth-library');

const Report = require("../models/report");

/**
 * @method - POST
 * @param - /
 * @description - Add new reports about tests or locations
 * @param {string} idUser
 * @param {string} testDate
 * @param {string} testResult
 * @returns {json} returns if it saved ok
 */


router.post(
    "/",
    auth,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const {
            idUser,
            testDate,
            testResult
        } = req.body;
        
        try {
            
            
            report = new Report({
                idUser,
                testDate,
                testResult
            });

            await report.save();

            const payload = {
                report: {
                    id: report.idReport
                }
            };

            
            res.status(200).json({
                report
            });
             
        } catch (err) {
            console.log(err.message);
            res.status(500).send("Error in Saving");
        }
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



module.exports = router;