
// Load passport local
var localStrategy = require('passport-local').Strategy
var facebookStrategy = require('passport-facebook').Strategy

// Load validator
var validator = require('validator')

// Load user model
var User = require('../model/user')

module.exports = function (passport) {
  // Serialize user
  passport.serializeUser(function (user, done) {
    done(null, user.id)
  })

  // Deserialize user
  passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
      done(err, user)
    })
  })

  // Passport signup
  passport.use('local-signup', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  },
    function (req, email, password, done) {
        // Check that the email is in the right format
      if (!validator.isEmail(email)) {
        return done(null, false, req.flash('loginMessage', 'That is not a valid email address'))
      }

        // Check that the password is at least 8 chars
      if (password.length < 8) {
        return done(null, false, req.flash('loginMessage', 'The password needs to be 8 chars long'))
      }

      process.nextTick(function () {
        User.findOne({ 'local.email': email }, function (err, user) {
          if (err) {
            return done(err)
          }
          if (user) {
            return done(null, false, req.flash('loginMessage', 'That email is already in use'))
          } else {
            var newUser = new User()
            newUser.local.email = email
            newUser.local.password = password
            newUser.save(function (err) {
              if (err) {
                console.log(err)
              }
              return done(null, newUser, req.flash('loginMessage', 'Logged in successfully'))
            })
          }
        })
      })
    }))

  // Passport login
  passport.use('local-login', new localStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  },
    function (req, email, password, done) {
      process.nextTick(function () {
        User.findOne({ 'local.email': email }, function (err, user) {
          if (err) {
            return done(err)
          }

          if (!user) {
            return done(null, false, req.flash('loginMessage', 'sorry no one by that email'))
          }

          user.validPassword(password, function (err, isMatch) {
            if (err) {
              return console.log(err)
            }
            if (isMatch) {
              return done(null, user, req.flash('loginMessage', 'Logged in successfully'))
            }

            return done(null, false, req.flash('loginMessage', 'sorry wrong password'))
          })
        })
      })
    }))

    // Passport facebook login
  passport.use('facebook', new facebookStrategy({
    clientID: '120436848543276',
    clientSecret: 'c6c45b296cfaa2f7a2d2625eeb67c483',
    callbackURL: 'http://localhost:3000/auth/facebook/callback',
    profileFields: ['name', 'email', 'link', 'locale', 'timezone'],
    passReqToCallback: true
  },
  function (req, accessToken, refreshToken, profile, done) {
    console.log(profile)

    User.findOne({ 'facebook.id': profile.id }, function (err, user) {
      if (err) {
        return done(err)
      }

      if (!user) {
        var newUser = new User()
        newUser.facebook.id = profile.id
        newUser.facebook.token = accessToken
        newUser.facebook.name = profile.first_name + ' ' + profile.middle_name + ' ' + profile.last_name
        newUser.facebook.email = profile.email
        newUser.save(function (err) {
          if (err) {
            console.log(err)
          }
          return done(null, newUser, req.flash('loginMessage', 'Logged in successfully'))
        })
      }

      if (user) {
        return done(null, user, req.flash('loginMessage', 'Logged in successfully'))
      }
    })
  }
))
}
