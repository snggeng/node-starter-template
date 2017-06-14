module.exports = function (app, passport) {
  // Routes
  // router middelware
  function isLoggedIn (req, res, next) {
    if (req.isAuthenticated()) {
      return next()
    }
    res.redirect('/')
  }

  // Sign up
  app.get('/', function (req, res) {
    res.render('signup', { message: req.flash('loginMessage') })
  })

  // Sign up
  app.post('/', passport.authenticate('local-signup', {
    successRedirect: '/secret',
    failureRedirect: '/',
    failureFlash: true
  }))

  // Login
  app.get('/login', function (req, res) {
    res.render('login', { message: req.flash('loginMessage') })
  })

  // Login
  app.post('/login', passport.authenticate('local-login', {
    successRedirect: '/secret',
    failureRedirect: '/login',
    failureFlash: true
  }))

    // Secret
  app.get('/secret', isLoggedIn, function (req, res) {
    res.render('secret', { message: req.flash('loginMessage') })
  })

  // logout
  app.get('/logout', function (req, res) {
    req.logout()
    res.redirect('/')
  })

  // facebook login
  app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'] }))

  app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
    res.redirect(req.session.returnTo || '/')
  })
}
