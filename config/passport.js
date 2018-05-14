const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./../models/User');

passport.serializeUser(function(user, done) {
    // console.log('serializeUser');
    done(null, user.creatorId);
});

passport.deserializeUser(function(id, done) {
    // console.log('deserializeUser');
    User.findOne({
        creatorId: id
    }, function(err, user) {
        done(null, user.creatorId);
    });
});

passport.use(new LocalStrategy(function(username, password, done) {

    User.findOne({
        username: username
    }).then(function(user) {
        if (!user) {
            return done(null, false, {
                message: 'Incorrect Credentials'
            })
        }
        let psswd = user ?
            user.password :
            '';
        user.comparePassword(password, psswd, function(err, found) {
            return done(err, found ?
                user :
                false);
        });
    }).catch(function(err) {
        console.error(err);
        done(null, false, {
            message: 'User does not exist'
        })
    });

}));