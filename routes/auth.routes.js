const bcrypt = require('bcrypt');
const saltRounds = 10;

const express = require('express');
const router = express.Router();

const User = require('../models/User.model');

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');


router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
    const { username, password } = req.body
    
    bcrypt
        .genSalt(saltRounds)
        .then(salt => bcrypt.hash(password, salt))
        .then(hashedPassword => {
            return User.create({ username, password: hashedPassword});
        })
        .then(createdUser => {
            console.log('Newly created user is: ', createdUser);
            res.redirect(`/auth/profile/${createdUser.username}`)
    })
    .catch(error => next(error));
});
 

router.get("/profile", isLoggedIn, (req, res, next) => {
    if(req.session.currentUser){
        User.findOne({ username: req.session.currentUser.username })
         .then(foundUser => {
             console.log('foundUser', foundUser)
             res.render('auth/profile', foundUser)
         })
         .catch(err => console.log(err))
     }
     else{
       res.render('auth/profile')
     }
 });


router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));

router.post('/login', (req, res,next) => {
    console.log('req.session', req.session)

    const { username, password } = req.body;

    if(username === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'Please enter both, username and password to login'
        });
        return;
    }

    User.findOne({ username })
        .then(user => {
            console.log('user', user)
            if(!user){
                res.render('auth/login', { errorMessage: 'Username is not registered. Try with other.' });
                return;
            } else if (bcrypt.compareSync(password, user.password)) {
                const { username, email } = user;
                req.session.currentUser = { username, email };
                res.render('auth/profile', user );
              } else {
                res.render('auth/login', { errorMessage: 'Incorrect password.' });
              }
            })
            .catch(error => next(error));
});


router.post('/logout', isLoggedIn, (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');
    });
  });


router.get('/main', isLoggedIn, (req, res, next) => res.render('auth/main'));



module.exports = router;
