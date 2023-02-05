const path = require('path');
require("dotenv").config()

// Reading environment variables from ".env" file
const userID = process.env.USER_ID
const password = process.env.PASSWORD

const express = require('express')
const session = require("express-session")
const mongodbStore = require("connect-mongodb-session")

const db = require('./data/database');
const demoRoutes = require('./routes/demo');

const MongoDBStore = mongodbStore(session)

const app = express();

const sessionStore = new MongoDBStore({
    uri: `mongodb+srv://${userID}:${password}@cluster0.v60qg.mongodb.net/?retryWrites=true&w=majority`,
    databaseName: "auth-demo",
    collection: "sessions"
})

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: "fynmaw-gawwy0-zuMmid",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}))

app.use(demoRoutes);

app.use(function (error, req, res, next) {
    res.render('500');
})

db.connectToDatabase().then(function () {
    app.listen(3000);
});
