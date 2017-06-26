const passport = require("passport");
const User = require("../models/user");
const config = require("../config");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

// Create local strategy
const localOptions = { usernameField: "email" };
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
    // Verify this email and password, call 'done' with the user if correct, Otherwise call 'done' with false
    User.findOne({ email }, (err, user) => {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false);
        }

        // compare passwords - is 'password' === user.password ?
        user.comparePasswords(password, (err, isMatch) => {
            if (err) {
                return done(err);
            }
            if (!isMatch) {
                return done(null, false)
            }

            return done(null, user); // user will be available through req.user
        });
    });
});

// Set up options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader("authorization"),
    secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
    // See if user ID in the payload exists in our database
    // If it does, call 'done' with that user
    // Otherwise, call 'done' without a user object
    User.findById(payload.sub, (err, user) => {
        if (err) {
            return done(err, false);
        }

        done(null, user || false);
    });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
