// middleware/route-guard.js

// checks if the user is logged in when trying to access a specific page
const isLoggedIn = (req, res, next) => {
    console.log('this is the session', req.session)
    if (!req.session.user) {
      return res.redirect('/users/login');
    }
    next();
  };
  
  // if an already logged in user tries to access the login page it
  // redirects the user to the home page
  const isLoggedOut = (req, res, next) => {
    if (req.session.user) {
      return res.redirect('/');
    }
    next();
  };
  
  module.exports = {
    isLoggedIn,
    isLoggedOut
  };
  