const express = require('express');
const bcrypt = require("bcrypt")

const db = require('../data/database');

const router = express.Router();


router.get('/', function (req, res) {
    res.render('welcome');
});


router.get('/signup', function (req, res) {
    let sessionInputData = req.session.inputData

    if (!sessionInputData) {
        sessionInputData = {
            hasError: false,
            email: "",
            confirmEmail: "",
            password: ""
        }
    }

    // Clear previous session data before rendering signup page
    req.session.inputData = null
    // Render the signup page and parse session data if any to the page.
    res.render('signup', { inputData: sessionInputData });
});


router.get('/login', function (req, res) {
    let sessionInputData = req.session.inputData

    if (!sessionInputData) {
        sessionInputData = {
            hasError: false,
            email: "",
            password: ""
        }
    }

    // Clear previous session data before rendering signup page
    req.session.inputData = null
    res.render('login', { inputData: sessionInputData });
});


router.post('/signup', async function (req, res) {
    // Get user data from request body
    const userData = req.body
    // Separate and assign each piece of inputs to different constants
    const enteredEmail = userData.email
    const enteredConfirmEmail = userData["confirm-email"]
    const enteredPassword = userData.password.trim()

    // Check whether given inputs have data OR they have valid data
    if (!enteredEmail ||
        !enteredConfirmEmail ||
        !enteredPassword ||
        enteredPassword.length < 6 ||
        enteredEmail != enteredConfirmEmail ||
        !enteredEmail.includes("@")
    ) {
        // Saving user temporary data to session, when validation fails
        req.session.inputData = {
            hasError: true,
            message: "Invalid input - please check your data",
            email: enteredEmail,
            confirmEmail: enteredConfirmEmail,
            password: enteredPassword
        }
        // If any of condition above doesn't meet, then redirect user back to "signup" page.
        // But before redirecting user; Save session data to session Database.
        req.session.save(function () {
            res.redirect("/signup")
        })
        return
    }
    // Check if we already have the email registered in our database
    const existingUser = await db.getDb().collection("users").findOne({ email: enteredEmail })
    // If email address exists in our database, then do not proceed and
    // redirect user back to signup page.
    if (existingUser) {
        // Save session data if user already exists
        req.session.inputData = {
            hasError: true,
            message: "User already exists!",
            email: enteredEmail,
            confirmEmail: enteredConfirmEmail,
            password: enteredPassword
        }
        // Save session data
        req.session.save(function () {
            res.redirect("/signup")
        })
        return
    }
    // Finally hash the given password
    const hashedPassword = await bcrypt.hash(enteredPassword, 12)
    // Create data object to go in database
    const user = {
        email: enteredEmail,
        password: hashedPassword,
    }
    // Save user data (email and password) in the database
    await db.getDb().collection("users").insertOne(user)

    // // Clear temporary session user's data (email(s) and passwords)
    // req.session.inputData = {
    //     email: "",
    //     confirmEmail: "",
    //     password: ""
    // }
    // // Save nullify session data to database
    // req.session.save(function () {
    //     // Then redirect user to "login" route
    //     res.redirect("/login")
    // })
    res.redirect("/login")
});


// User logon route to allow user to authenticate.
router.post('/login', async function (req, res) {
    // Create reference to the received/parsed data with request
    const userData = req.body
    // Separate each piece of input and assign them different constants
    const enteredEmail = userData.email
    const enteredPassword = userData.password
    // Check if the user's email already exists in our database.
    const existingUser = await db.getDb().collection("users").findOne({ email: enteredEmail })
    // And if user's email doesn't exists/registered in database, redirect to login again
    if (!existingUser) {
        req.session.inputData = {
            hasError: true,
            message: "Logon Error! please check your credentials",
            email: enteredEmail,
            password: enteredPassword
        }
        req.session.save(function () {
            res.redirect("/login")
        })
        return
    }
    // Otherwise, check if user's parsed password is same as in our database
    const passwordsAreEqual = await bcrypt.compare(enteredPassword, existingUser.password)
    // If password isn't equal to the one stored in database, redirect to login again
    if (!passwordsAreEqual) {
        req.session.inputData = {
            hasError: true,
            message: "Logon Error!, please check your credentials",
            email: enteredEmail,
            password: enteredPassword
        }
        req.session.save(function () {
            res.redirect("/login")
        })
        return
    }
    // Add data to session
    req.session.user = { id: existingUser._id, email: existingUser.email }
    req.session.isAuthenticated = true
    req.session.save(function () {
        res.redirect("/profile")
    })
    // Finally user get authenticated, passing all above conditions
    console.log("User is authenticated")
});


router.get('/admin', async function (req, res) {
    if (!req.session.isAuthenticated) { // if (!req.session.user)
        return res.status(401).render("401")
    }
    const user = await db.getDb().collection("users").findOne({ _id: req.session.user.id })
    if (!user || !user.isAdmin) {
        return res.status(403).render("403")
    }
    res.render('admin');
});


router.get('/profile', function (req, res) {
    if (!req.session.isAuthenticated) { // if (!req.session.user)
        return res.status(401).render("401")
    }
    res.render('profile');
});


router.post('/logout', function (req, res) {
    req.session.user = null
    req.session.isAuthenticated = false
    // Save above values to session
    req.session.save(function () {
        res.redirect("/")
    })
});


module.exports = router;
