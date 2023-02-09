var express = require('express');
var router = express.Router();

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model')
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js'); // calling in middleware


/* GET users listing. */
router.get('/signup', isLoggedOut,(req, res, next) =>{
  res.render('auth/signup.hbs');
});

router.post('/signup', isLoggedOut,(req,res, next ) => { 
  console.log('The form data: ', req.body);

  const { username, password } = req.body;
  
  if (!username || !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }
 
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => {
      return bcryptjs.hash(password, salt)
    })
    .then((hashedPassword) => {
      return User.create({
      
            username: req.body.username,
            password: hashedPassword
          });
        })
        .then(userFromDB => {
          console.log('Newly created user is: ', userFromDB);
          res.redirect('/users/login')
        })
    
        .catch((error) => {
          if (error instanceof mongoose.Error.ValidationError) {
          res.status(500).render('auth/signup', { errorMessage: error.message });
        } else if (error.code === 11000) {
          res.status(500).render('auth/signup', {
              errorMessage: 'Username and email need to be unique. Either username or email is already used.'
          });
        } else {
          next(error);
        }
          });
    });
// Login 
router.get('/login', (req,res,next) => {
  res.render('auth/login.hbs')
});

//verification of user credentials
router.post('/login', (req, res, next) => {
  const { username, password } = req.body;
 
  if (!username || !password) {
    res.render('auth/login.hbs', {
      errorMessage: 'Please enter both, username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Username is not registered. Try with other email.' });
        return;
      } else if (bcryptjs.compareSync(password, user.password)) {
        req.session.user = user
        console.log('SESSION =====> ', req.session);
        res.redirect('/users/profile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});

router.get('/profile', isLoggedIn, (req, res, next) => {
const user = req.session.user
console.log('SESSION =====> ', req.session);
res.render('users/user-profile.hbs', {user})
});

router.get('/logout', isLoggedIn,(req, res, next) => {
req.session.destroy(err => {
if (err) next(err);
res.redirect('/');
});

//main
router.get('/main', isLoggedIn, (req, res, next) => {
  console.log('trying to get back to main',req.body)
  res.render ('users/main.hbs')
});

//private
router.get('/private',isLoggedIn,(req, res, next) => {
  res.render('users/private.hbs')
});

});




module.exports = router;
