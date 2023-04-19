require('dotenv').config();
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

//Production Grade Session Store - production application stores session data in a variety of ways here we use MongoDb
const MongoDBStore = require('connect-mongodb-session')(session)

var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions'
});

// Catch errors
store.on('error', function (error) {
  console.log(error);
});


const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

//Function 1- setting up the Local Strategy// function will be called when we use passport.authenticate- function takes
//function takes username & password and tries to find the user in our DB, and then makes suree that user's password matches given password
passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await User.findOne({ username: username });
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password" });
          }
        });
      } catch (err) {
        return done(err);
      }
    })
  );

//Function 2 & 3 - These functions define what bit of information passport is looking gor when it creates and the decodes the cookie.
//Purpose of defining functions is to make sure that whatever bit of data it's looking for exists in our database
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(async function(id, done) {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch(err) {
      done(err);
    };
  });



app.use(session({
    secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true,
    store: store
  }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//gives access to the currentUser
app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
  });

app.get("/", (req, res) => {
    let messages = [];
    if (req.session.messages) {
      messages = req.session.messages;
      req.session.messages = [];
    }
    res.render("index", { messages });
  });

  //Access Control- certain pages are restricted only to those users that log in
  const authMiddleware = (req, res, next) => {
    if (!req.user) {
      if (!req.session.messages) {
        req.session.messages = [];
      }
      req.session.messages.push("You can't access that page before logon.");
      res.redirect('/');
    } else {
      next();
    }
  }



