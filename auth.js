const LocalStrategy =require('passport-local');
const passport=require('passport');
const bcrypt=require('bcryptjs');
const ObjectID = require('mongodb').ObjectID;

const session= require('express-session');
     
// *!STORE SESSION ID FOR SESSION        
const MongoStore=require('connect-mongo')(session);

module.exports=function(app,db){

    app.use(session({
        secret:'MySecret', //process.env.SESSION_SECRET,==this is for production
        resave: true,
        saveUninitialized: true,
     // *! THIS CONNECT TO DATABSE AND STORE SESSION ID     
        store: new MongoStore({ url: 'mongodb://localhost/login' }) 
      }));
      
      app.use(passport.initialize());
      app.use(passport.session());
     // *!SERIALIZE AND DESIRIALIZE USER       
     passport.serializeUser((user, done) => {
        done(null, user._id);
      });

      passport.deserializeUser( (id, done) => {
          db.collection('users').findOne(
              {_id: new ObjectID(id)},
              (err, doc) => {
                  done(null, doc);
              }
          );
      });

      // *! PASSPORT STRATEGY LOCAL   
      passport.use(new LocalStrategy(
        function(username, password, done) {
          db.collection('users').findOne({ username: username }, function (err, user) {
            console.log('User '+ username +' attempted to log in.');
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            // if (password !== user.password) { return done(null, false); }//** */!REPLACED BCOZ OF HASHING 
            if(!bcrypt.compareSync(password,user.password)){return done(null,false);}
            return done(null, user);
          });
        }
      ));
}