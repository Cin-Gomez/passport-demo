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

//Production Grade Session Store
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


//ROUTES:

//1.route for sign up form
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

//2. app.post for the sign up form- to add users to our database
app.post("/sign-up", async (req, res, next) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      await User.create({ username: req.body.username, password: hashedPassword });
      res.redirect("/");
    } catch (err) {
      return next(err);
    }
  });

//3. route - if login is a success or failure
app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/",
        failureMessage: true
      }));
  

  //4.route - logout route
  app.get("/log-out", (req, res) => {
    req.session.destroy(function (err) {
      res.redirect("/");
    });
  });

  //5. route - loads page for unauthorized user
  app.get('/restricted', authMiddleware, (req, res) => {
    if (!req.session.pageCount) {
      req.session.pageCount = 1;
    } else {
      req.session.pageCount++;
    }
    res.render('restricted', { pageCount: req.session.pageCount });
  })



app.listen(3000, () => console.log("app listening on port 3000!"));

