require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useUnifiedTopology: true,
  useNewUrlParser: true,
  useCreateIndex: true
});

const userSchema = new mongoose.Schema({
  username: {type: String, unique: true},
  password: String,
  provider: String,
  email: String
});

userSchema.plugin(passportLocalMongoose, {usernameField: "username"});
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id)
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({username: profile.id},
      {
        provider: profile.provider,
        email: profile._json.email
      },
      function (err, user) {
        return cb(err, user);
    });
  }
));

app.route("/")
  .get(function(req, res) {
    res.render("home");
  });

app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })
  // .post(function(req, res) {
  //   const user = new User({
  //     username: req.body.username,
  //     password: req.body.password
  //   });
  //   req.login(user, function(err) {
  //     if (err) {
  //       console.log(err);
  //       req.logout();
  //       res.redirect("/login");
  //     } else {
  //       passport.authenticate("local")(req, res, function() {
  //         res.redirect("/secrets");
  //       });
  //     }
  //   });
  // });

  .post(passport.authenticate("local", { successRedirect: '/secrets', failureRedirect: '/login' }));

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

// Google authentication

app.get("/auth/google", passport.authenticate("google", {scope: ["profile", "email"]}));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res) {
    const username = req.body.username;
    const password = req.body.password;
    User.register({
      username: username,
      email: username,
      provider: "local"
    }, password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    });
  });

app.listen(3000, function() {
  console.log("server started on port 3000");
});
