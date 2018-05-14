const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passportLocalMongoose = require('passport-local-mongoose');

const saltFactor = 10;
const Schema = mongoose.Schema;

// defining two schemas, TradeScheme will be used for both incoming and outgoing trades, Poll will be child of User - to create nesting of documents. Better for data manipulation and aggregation.


const TradeSchema = new Schema({
    book: {
        type: Schema.Types.ObjectId,
        ref: 'Book',
        required: true
    },
    tradeType: {
        type: String,
        required: true,
        default: 'request'
    },
    owner: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    recipient: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    dateRequested: {
        type: Date,
        default: Date.now,
        required: true
    },
    dateOut: {
        type: Date
    }
});
const UserSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        validate: {
            validator: function(v) {
                return /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-_])[A-z0-9#?!@$%^&*-_]{8,}$/.test(v);
            },
            message: 'Password must be at least 8 characters in length include at least 1 lowercase letter, 1 capital letter, 1 number and 1 special character (ie. #?!@$%^&*-_).'
        }
    },
    creatorId: {
        type: String,
        required: true
    },
    firstName: String,
    lastName: String,
    city: String,
    state: String,
    zipCode: String,
    books: [{
        type: Schema.Types.ObjectId,
        ref: 'Book'
    }],
    tradesOut: [TradeSchema],
    tradesIn: [TradeSchema]
});

UserSchema.plugin(passportLocalMongoose);

// Pre-save of user to database, hash password if password is modified or new
UserSchema.pre('save', function(next) {
    const user = this;
    if (!user.isModified('password')) return next();

    bcrypt.genSalt(saltFactor, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        })
    })
});

UserSchema.method('comparePassword', function(candidatePassword, dbPassword, cb) {
    bcrypt.compare(candidatePassword, dbPassword, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
});


module.exports = mongoose.model('User', UserSchema);