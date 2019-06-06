'use strict'

const express = require('express');
const bodyParser = require('body-parser');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
// const io = require('socket.io')
const mongoose = require('mongoose');
const session = require('express-session');
const LocalStrategy = require('passport-local');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const flash=require('express-flash');
const async =require('async');
const crypto = require('crypto');
const cookieParser=require('cookie-parser');
const nodemailer=require('nodemailer');


// const passport    = require('passport');
// const LocalStrategy= require('passport-local');
// const session= require('express-session');
// const bcrypt=require('bcryptjs');
//*! DATABASE
const ObjectID = require('mongodb').ObjectID
// const mongo    = require('mongodb').MongoClient;

//*! REQUIRING THE AUTHENTICATION AND ROUTE FILES
// const routes   =require('./routes');
// const auth     =require('./auth');
const { User } = require('./User')

const app = express()
app.use(cookieParser());

//*! SET ENGINE(PUG)
app.set('view engine', 'pug')

// *!STORE SESSION ID FOR SESSION
const MongoStore = require('connect-mongo')(session)
// fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'))
app.use(bodyParser.json())
app.use(
  bodyParser.urlencoded({
    extended: true
  })
)

mongoose.connect(
  'mongodb://localhost:27017/mongologin',
  {
    useNewUrlParser: true
  },
  err => {
    if (err) {
      console.log('Database error: ' + err)
    } else {
      console.log('Successful database connection')

      // var db = client.db('login');//*! VERY MUCH IMPORTANT FOR MONGO 3.X.X
      // *!AUTHENTICATION
      // auth(app,db);
      var db = mongoose.connection

      app.use(
        session({
          secret: 'MySecret', //process.env.SESSION_SECRET,==this is for production
          resave: true,
          saveUninitialized: true,
          // *! THIS CONNECT TO DATABSE AND STORE SESSION ID
          store: new MongoStore({
            mongooseConnection: mongoose.connection
          })
        })
      )
      app.use(flash()); //! USING EXPRESS-FLASH
      //* mongoose.connection=db=mongoose.connection[0] //db.on(..) //db.once(..)
      app.use(passport.initialize())
      app.use(passport.session())

      // *!SERIALIZE AND DESIRIALIZE USER
      passport.serializeUser((user, done) => {
        done(null, user._id)
      })

      passport.deserializeUser((id, done) => {
        db.collection('users').findOne(
          {
            _id: new ObjectID(id)
          },
          (err, doc) => {
            done(null, doc)
          }
        )
      })

      // *! PASSPORT STRATEGY LOCAL
      passport.use(
        new LocalStrategy(function(username, password, done) {
          User.findOne(
            {
              username: username
            },
            function(err, user) {
              console.log('User ' + username + ' attempted to log in.')
              if (err) {
                return done(err)
              }
              if (!user) {
                return done(null, false)
              }
              // if (password !== user.password) { return done(null, false); }//** */!REPLACED BCOZ OF HASHING
              if (!bcrypt.compareSync(password, user.password)) {
                return done(null, false)
              }
              return done(null, user)
            }
          )
        })
      )

      // routes(app,db);
      // *!ROUTES

      // *! ENSURE AUTHENTICATION READ BELOW
      //** The challenge here is creating the middleware function
      //** ensureAuthenticated(req, res, next), which will check
      //** if a user is authenticated by calling passports isAuthenticated
      //** on the request which in turn checks for req.user is to be defined.
      //** If it is then next() should be called, otherwise we can just respond
      //**  to the request with a redirect to our homepage to login.
      //**  An implementation of this middleware is:

      const ensureAuthenticated = (req, res, next) => {
        if (req.isAuthenticated()) {
          return next()
        }
        res.redirect('/')
      }

      // *! HOME ROUTE
      app.route('/').get((req, res) => {
        if (req.user) {
          res.redirect('/profile')
          console.log(req.user)
        } else {
          res.render(process.cwd() + '/views/pug/index', {
            title: 'Hello',
            message: 'login',
            showLogin: true,
            showRegistration: true
          })
        }
      })

      // *! LOGIN ROUTE
      app.route('/login').post(
        passport.authenticate('local', {
          failureRedirect: '/'
        }),
        (req, res) => {
          res.redirect('/profile')
        }
      )
      // *!LOGOUT ROUTE
      app.route('/logout').get((req, res) => {
        req.logout()
        res.redirect('/')
      })
      // *!CHANGE PASS ROUTE
      app.route('/passChange').post((req,res)=>{
        User.findOne({_id:req.user._id},function(err,doc){

          if(err){ return console.log('failed to save ')}
          else{
            if(req.body.password===req.body.confirmpassword){
            doc.password=req.body.password;
            doc.save();
            console.log(`password changed successfully of USER:${req.user.username}`) 
       }
      }
      res.redirect('/profile');
        }
      )
    })
      // *!REGISTRATION ROUTE
      app.route('/register').post(
        (req, res, next) => {
          //    var username=req.body.username;
          // const password=req.body.password;
          // res.send(req.body);
          User.findOne(
            {
              username: req.body.username
            },
            function(err, user) {
              if (err) {
                next(err)
              } else if (user) {
                res.redirect('/')
              } else {
                //  var hash = bcrypt.hashSync(req.body.password, 12);
                var client = new User()
                client.username = req.body.username
                client.password = req.body.password
                client.email = req.body.email                
                client.save(function(err, client) {
                  if (err) {
                    res.redirect('/')
                  } else {
                    next(null, client)
                  }
                })
              }
            }
          )
        },
        passport.authenticate('local', {
          failureRedirect: '/'
        }),
        (req, res, next) => {
          res.redirect('/profile')
        }
      )
      // *! PROFILE ROUTE
      app.route('/profile').get(ensureAuthenticated, (req, res) => {
        res.render(process.cwd() + '/views/pug/profile', {
          username: `${req.user.username}`,
          
        })
      })
      // *! FORGOT ROUTE GET
      app.get('/forgot', function(req, res) {
        res.render(process.cwd() + '/views/pug/forgot', {
          user: req.user
        });
      });
      // *! FORGOT ROUTE POST
      app.post('/forgot', function(req, res, next) {
        async.waterfall([
          function(done) {
            crypto.randomBytes(20, function(err, buf) {
              var token = buf.toString('hex');
              done(err, token);
            });
          },
          function(token, done) {
            User.findOne({ email: req.body.email }, function(err, user) {
              if (!user) {
                req.flash('error', 'No account with that email address exists.');
                return res.redirect('/forgot');
              }
      
              user.resetPasswordToken = token;
              user.resetPasswordExpires = Date.now() + 1800000; //! 30 minutes
      
              user.save(function(err) {
                done(err, token, user);
              });
            });
          },
          function(token, user, done) {
            var client = nodemailer.createTransport( {
              service: 'SendGrid',
              auth: {
                user: '#SENDGRID USERNAME',
                pass:'#SENDGRID PASSWORD'
              }
            });
            var Options = {
              to: user.email,
              from: 'passwordreset@demo.com',
              subject: 'Node.js Password Reset',
              text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
            client.sendMail(Options, function(err,info) {
              req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
              done(err, 'done');
            });
          }
        ], function(err) {
          if (err) return next(err);
          res.redirect('/forgot');
        });
      });
      // *!RESET ROUTE GET
      app.get('/reset/:token', function(req, res) {
        User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
          if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
          }
          res.render(process.cwd() + '/views/pug/reset', {
            user: req.user
          });
        });
      });

      // *!RESET ROUTE GET
      app.post('/reset/:token', function(req, res) {
        async.waterfall([
          function(done) {
            User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
              if (!user) {
                req.flash('error', 'Password reset token is invalid or has expired.');
                return res.redirect('back');
              }
      
              user.password = req.body.password;
              user.resetPasswordToken = undefined;
              user.resetPasswordExpires = undefined;
      
              user.save(function(err) {
                req.logIn(user, function(err) {
                  done(err, user);
                });
              });
            });
          },
          function(user, done) {
            var client = nodemailer.createTransport( {
              service: 'SendGrid',
              auth: {
                user: '#SENDGRID USERNAME',
                pass:'#SENDGRID PASSWORD'
              
              }
            });
            var Options = {
              to: user.email,
              from: 'passwordreset@demo.com',
              subject: 'Your password has been changed',
              text: 'Hello,\n\n' +
                'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
            };
            client.sendMail(Options, function(err,info) {
              req.flash('success', 'Success! Your password has been changed.');
              done(err);
            });
          }
        ], function(err) {
          res.redirect('/');
        });
      });

      // *!HANDLING MISSING PAGES (404)
      app.use((req, res, next) => {
        res
          .status(404)
          .type('text')
          .send('Not Found')
      })

      var port = process.env.PORT || 3000
      app.listen(port, () => {
        console.log('Listening on port ' + port)
      })
    }
  }
)
