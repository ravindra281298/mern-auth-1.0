const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");

//Load input validation
const validateRegisterInput = require("../../Validation/register");
const validateLoginInput = require("../../Validation/login");

//Load Users model
const User = require("../../models/User");


//@router POST api/users/register
//@desc Register user
//@access Public
router.post("/register", (req,res) => {
    //Form validation
    const { errors, isValid } = validateRegisterInput(req.body);
    
    //check validation
    if(!isValid) {
        return res.status(400).json(errors);
    }
    User.findOne({email: req.body.email}).then(user => {
        if(user) {
            return res.status(400).json({email:"email already exists"});
        } else {
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password
            });

            //Hash password before saving in database
            bcrypt.genSalt(10,(err,salt) => {
                bcrypt.hash(newUser.password, salt, (err,hash) => {
                    if(err) {
                        throw err;
                    }
                    newUser.password = hash;
                    newUser
                    .save()
                    .then(user => res.json(user))
                    .catch(err => console.log(err));
                });
            });
        }
    });
});


//@router POST api/users/login
//@desc Login user and return JWT token
//@access Public
router.post("/login", (req,res) => {
    //Form validation
    const { errors, isValid } = validateLoginInput(req.body);

    //Check validation
    if(!isValid) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    //Find user by email
    User.findOne({ email }).then(user => {
        if(!user) {
            return res.status(400).json({ emailnotfound: "Email not found"});
        }
        bcrypt.compare(password,user.password).then(isMatch => {
            if(isMatch) {
                // user matched create JWT token
                const payload = {
                    id:user.id,
                    name: user.name
                };

                //sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926 // 1 year in second
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            token: "Bearer "+ token
                        });
                    }
                );
            } else {
                return res
                .status(400)
                .json({ passwordincorrect: "passwor incorrect"});
            }
        });
    });
});

module.exports = router;