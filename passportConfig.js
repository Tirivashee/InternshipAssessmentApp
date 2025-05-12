const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { pool } = require('./dbConfig');

function initialize(passport) {
    const authenticateUser = (email, password, done) => {
        pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email],
            (err, result) => {
                if (err) {
                    console.error('Database error during user authentication:', err);
                    return done(err);
                }

                if (result.rows.length > 0) {
                    const user = result.rows[0];

                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if (err) {
                            console.error('Error during password comparison:', err);
                            return done(err);
                        }

                        if (isMatch) {
                            return done(null, user);
                        } else {
                            return done(null, false, { message: "Incorrect password" });
                        }
                    });
                } else {
                    return done(null, false, { message: "No user with that email" });
                }
            }
        );
    };

    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    }, authenticateUser));

    passport.serializeUser((user, done) => {
        // Store user ID and role in session data
        done(null, { id: user.id, role: user.role });
    });

    passport.deserializeUser((sessionData, done) => {
        // Retrieve user by ID from database and add role from session to the user object
        pool.query(
            'SELECT id, username, email, role FROM users WHERE id = $1',
            [sessionData.id],
            (err, result) => {
                if (err) {
                    console.error('Error retrieving user during session deserialization:', err);
                    return done(err);
                }

                if (result.rows.length > 0) {
                    const user = result.rows[0];
                    // Attach the role from the session data to ensure consistency
                    user.role = sessionData.role;
                    return done(null, user);
                } else {
                    return done(null, false);
                }
            }
        );
    });
}

module.exports = initialize;
